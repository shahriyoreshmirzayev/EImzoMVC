using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;

namespace EImzoMVC;

public class SignatureController : Controller
{
    private readonly ISignatureService _signatureService;
    private readonly ILogger<SignatureController> _logger;
    private readonly Services.EImzoService? _eImzoService;
    private readonly Models.EImzoConfig _eImzoConfig;

    public SignatureController(ISignatureService signatureService, ILogger<SignatureController> logger, Services.EImzoService? eImzoService = null, Models.EImzoConfig? eImzoConfig = null)
    {
        _signatureService = signatureService;
        _logger = logger;
        _eImzoService = eImzoService;
        _eImzoConfig = eImzoConfig ?? new Models.EImzoConfig();
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Sign()
    {
        return View(new SignDocumentViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoteCreateChallenge(SignDocumentViewModel model)
    {
        if (model?.DocumentFile == null)
        {
            ModelState.AddModelError("", "Hujjat faylini tanlang");
            return View("Sign", model);
        }

        try
        {
            byte[] documentData;
            using (var ms = new MemoryStream())
            {
                await model.DocumentFile.CopyToAsync(ms);
                documentData = ms.ToArray();
            }

            // Store original document in session until callback
            HttpContext.Session.Set("RemoteOriginalData", documentData);
            HttpContext.Session.SetString("RemoteOriginalFileName", model.DocumentFile.FileName);

            // Compute SHA256 digest as challenge
            using var sha = System.Security.Cryptography.SHA256.Create();
            var hash = sha.ComputeHash(documentData);
            var challenge = Convert.ToBase64String(hash);

            ViewBag.Challenge = challenge;
            return View("RemoteSign");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Remote challenge creation failed");
            ModelState.AddModelError("", "Challenge yaratishda xatolik");
            return View("Sign", model);
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ESignIn([FromForm] Models.ESignInModel model)
    {
        // Sign out existing session
        await HttpContext.SignOutAsync();

        if (_eImzoService == null)
            return BadRequest(new { success = false, message = "E-Imzo service not configured" });

        try
        {
            // Timestamp (using PKCS#7 timestamp endpoint on remote)
            var tsDto = new Models.EImzoTimeStampDto { SignData = model.Sign };
            var timeStamp = await _eImzoService.TimeStamp(tsDto.SignData);

            // If idcard, populate Inn/Pinfl from timestamp
            if (model.KeyId?.ToLower() == "idcard")
            {
                model.Inn = timeStamp.TimestampedSignerList.FirstOrDefault()?.SubjectName.Inn;
                model.Pinfl = timeStamp.TimestampedSignerList.FirstOrDefault()?.SubjectName.Pinfl;
            }

            // Verify attached PKCS#7 on remote
            var verify = await _eImzoService.VerifyAttached(new Models.EImzoVerifyDto { SignData = timeStamp.Pkcs7b64 });

            // Parse original document from verify response
            var documentBase64 = verify.Pkcs7Info.DocumentBase64;
            var documentBytes = Convert.FromBase64String(documentBase64);
            var documentJson = System.Text.Encoding.UTF8.GetString(documentBytes);

            Models.ESignInResponseModel signedContent;
            try
            {
                var jo = Newtonsoft.Json.Linq.JObject.Parse(documentJson);
                var uzasbo = jo["uzasbo"] as Newtonsoft.Json.Linq.JObject;
                if (uzasbo != null)
                    signedContent = uzasbo.ToObject<Models.ESignInResponseModel>();
                else
                    signedContent = Newtonsoft.Json.JsonConvert.DeserializeObject<Models.ESignInResponseModel>(documentJson);
            }
            catch
            {
                return BadRequest(new { success = false, message = "Invalid signed document format" });
            }

            // Validate request exists - placeholder repository logic
            // var eSignInRequest = _userESignInRequestRepository.ByUniqueKey(signedContent.RequestId);
            // if (eSignInRequest == null || eSignInRequest.CreatedAt.AddMinutes(10) < DateTime.Now) { ... }

            // Determine user by Pinfl/Inn - placeholder, adapt to your repositories
            // User user = FindUserBySignedContent(signedContent, verify);

            // For demo return parsed content and verify info
            return Json(new { success = true, signed = signedContent, verify = verify });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ESignIn failed");
            return StatusCode(500, new { success = false, message = "Internal error" });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Sign(SignDocumentViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            byte[] documentData;
            using (var ms = new MemoryStream())
            {
                await model.DocumentFile.CopyToAsync(ms);
                documentData = ms.ToArray();
            }

            byte[] certificateData;
            using (var ms = new MemoryStream())
            {
                await model.CertificateFile.CopyToAsync(ms);
                certificateData = ms.ToArray();
            }

            var result = await _signatureService.SignDocumentAsync(documentData, certificateData, model.Password);

            if (result.Success)
            {
                HttpContext.Session.Set("SignedData", result.SignedData);
                HttpContext.Session.SetString("OriginalFileName", model.DocumentFile.FileName);

                TempData["SuccessMessage"] = result.Message;
                TempData["SignerInfo"] = Newtonsoft.Json.JsonConvert.SerializeObject(result.SignerInfo);

                return RedirectToAction(nameof(SignResult));
            }
            else
            {
                ModelState.AddModelError("", result.Message);
                return View(model);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Imzolashda xatolik");
            ModelState.AddModelError("", $"Xatolik yuz berdi: {ex.Message}");
            return View(model);
        }
    }

    public IActionResult SignResult()
    {
        if (TempData["SuccessMessage"] == null)
        {
            return RedirectToAction(nameof(Sign));
        }

        ViewBag.Message = TempData["SuccessMessage"];

        if (TempData["SignerInfo"] != null)
        {
            ViewBag.SignerInfo = Newtonsoft.Json.JsonConvert.DeserializeObject<SignerInfo>(TempData["SignerInfo"].ToString());
        }

        return View();
    }

    public IActionResult DownloadSigned()
    {
        var signedData = HttpContext.Session.Get("SignedData");
        var originalFileName = HttpContext.Session.GetString("OriginalFileName");

        if (signedData == null || string.IsNullOrEmpty(originalFileName))
        {
            return RedirectToAction(nameof(Sign));
        }

        var fileName = $"{Path.GetFileNameWithoutExtension(originalFileName)}.p7s";
        return File(signedData, "application/pkcs7-signature", fileName);
    }

    public IActionResult Verify()
    {
        return View(new VerifySignatureViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Verify(VerifySignatureViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            byte[] signedData;
            using (var ms = new MemoryStream())
            {
                await model.SignedFile.CopyToAsync(ms);
                signedData = ms.ToArray();
            }

            var result = await _signatureService.VerifySignatureAsync(signedData);

            if (result.IsValid)
            {
                if (result.OriginalData != null)
                {
                    HttpContext.Session.Set("OriginalData", result.OriginalData);
                    HttpContext.Session.SetString("VerifiedFileName", model.SignedFile.FileName);
                }
            }

            ViewBag.Result = result;
            return View("VerifyResult", result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Tekshirishda xatolik");
            ModelState.AddModelError("", $"Xatolik yuz berdi: {ex.Message}");
            return View(model);
        }
    }

    public IActionResult DownloadOriginal()
    {
        var originalData = HttpContext.Session.Get("OriginalData");
        var verifiedFileName = HttpContext.Session.GetString("VerifiedFileName");

        if (originalData == null || string.IsNullOrEmpty(verifiedFileName))
        {
            return RedirectToAction(nameof(Verify));
        }

        var fileName = Path.GetFileNameWithoutExtension(verifiedFileName.Replace(".p7s", ""));
        return File(originalData, "application/octet-stream", fileName);
    }

    public async Task<IActionResult> Certificates()
    {
        var certificates = await _signatureService.GetInstalledCertificatesAsync();
        var model = new CertificateListViewModel
        {
            Certificates = certificates
        };
        return View(model);
    }

    [HttpPost]
    [IgnoreAntiforgeryToken]
    [Microsoft.AspNetCore.Authorization.AllowAnonymous]
    public async Task<IActionResult> RemoteSignCallback([FromBody] Models.RemoteSignCallbackDto dto)
    {
        // If external app posted raw PKCS#7 signed data (base64 or hex), verify and store it locally.
        try
        {
            byte[] signedBytes = null;

            if (!string.IsNullOrWhiteSpace(dto?.SignData))
            {
                var s = dto.SignData.Trim();
                // Try base64
                try
                {
                    signedBytes = Convert.FromBase64String(s);
                }
                catch
                {
                    // Try hex
                    try
                    {
                        if (s.Length % 2 == 0)
                        {
                            signedBytes = Enumerable.Range(0, s.Length / 2)
                                .Select(i => Convert.ToByte(s.Substring(i * 2, 2), 16))
                                .ToArray();
                        }
                    }
                    catch
                    {
                        signedBytes = null;
                    }
                }
            }

            if (signedBytes != null && signedBytes.Length > 0)
            {
                // Verify the provided PKCS#7
                var verifyResult = await _signatureService.VerifySignatureAsync(signedBytes);
                if (verifyResult != null && verifyResult.IsValid)
                {
                    // Save signed data and original filename placeholder
                    HttpContext.Session.Set("SignedData", signedBytes);
                    HttpContext.Session.SetString("OriginalFileName", verifyResult.SignerInfo?.SubjectName ?? "signed_document");

                    return Json(new { success = true, message = "Signed data received and verified", signer = verifyResult.SignerInfo });
                }

                return Json(new { success = false, message = "Signed data is invalid or verification failed" });
            }

            // Fallback: if remote EImzo service is configured, call its Auth endpoint with signData
            if (_eImzoService != null)
            {
                var auth = await _eImzoService.AuthAsync(dto.SignData);
                return Json(new { success = auth != null && auth.Status == 1, message = auth?.Message });
            }

            return BadRequest(new { success = false, message = "No valid signed data provided and remote service not configured" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RemoteSignCallback failed");
            return StatusCode(500, new { success = false, message = "Internal error" });
        }
    }
}
