using EImzoMVC.Models;
using EImzoMVC.Services;
using Microsoft.AspNetCore.Mvc;

namespace EImzoMVC.Controllers
{
    public class SignatureController : Controller
    {
        private readonly ISignatureService _signatureService;
        private readonly ILogger<SignatureController> _logger;

        public SignatureController(ISignatureService signatureService, ILogger<SignatureController> logger)
        {
            _signatureService = signatureService;
            _logger = logger;
        }

        // GET: Signature/Index
        public IActionResult Index()
        {
            return View();
        }

        // GET: Signature/Sign
        public IActionResult Sign()
        {
            return View(new SignDocumentViewModel());
        }

        // POST: Signature/Sign
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
                // Hujjat faylini o'qish
                byte[] documentData;
                using (var ms = new MemoryStream())
                {
                    await model.DocumentFile.CopyToAsync(ms);
                    documentData = ms.ToArray();
                }

                // Sertifikat faylini o'qish
                byte[] certificateData;
                using (var ms = new MemoryStream())
                {
                    await model.CertificateFile.CopyToAsync(ms);
                    certificateData = ms.ToArray();
                }

                // Imzolash
                var result = await _signatureService.SignDocumentAsync(documentData, certificateData, model.Password);

                if (result.Success)
                {
                    // Imzolangan faylni sessiyaga saqlash
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

        // GET: Signature/SignResult
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

        // GET: Signature/DownloadSigned
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

        // GET: Signature/Verify
        public IActionResult Verify()
        {
            return View(new VerifySignatureViewModel());
        }

        // POST: Signature/Verify
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
                // Imzolangan faylni o'qish
                byte[] signedData;
                using (var ms = new MemoryStream())
                {
                    await model.SignedFile.CopyToAsync(ms);
                    signedData = ms.ToArray();
                }

                // Tekshirish
                var result = await _signatureService.VerifySignatureAsync(signedData);

                if (result.IsValid)
                {
                    // Asl ma'lumotni sessiyaga saqlash
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

        // GET: Signature/DownloadOriginal
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

        // GET: Signature/Certificates
        public async Task<IActionResult> Certificates()
        {
            var certificates = await _signatureService.GetInstalledCertificatesAsync();
            var model = new CertificateListViewModel
            {
                Certificates = certificates
            };
            return View(model);
        }
    }
}
