using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace EImzoMVC;

public class SignatureService : ISignatureService
{
    private readonly ILogger<SignatureService> _logger;

    public SignatureService(ILogger<SignatureService> logger)
    {
        _logger = logger;
    }

    public async Task<SignatureResult> SignDocumentAsync(byte[] documentData, byte[] certificateData, string password)
    {
        try
        {
            _logger.LogInformation("Hujjatni imzolash boshlandi...");
              
            X509Certificate2 certificate = null;
            var attempts = new[] {
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
            };

            Exception lastEx = null;
            foreach (var flags in attempts)
            {
                try
                {
                    var primary = new X509Certificate2(certificateData, password, flags);
                    if (primary.HasPrivateKey)
                    {
                        certificate = primary;
                        break;
                    }

                    var collection = new X509Certificate2Collection();
                    collection.Import(certificateData, password, flags);
                    certificate = collection.OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey) ?? primary;
                    if (certificate.HasPrivateKey) break;
                }
                catch (Exception ex)
                { 
                    lastEx = ex;
                    _logger.LogDebug(ex, "PKCS#12 import attempt failed with flags {Flags}", flags);
                }
            }

            if (certificate == null)
            { 
                if (lastEx is CryptographicException && lastEx.Message.Contains("The specified network password is not correct", StringComparison.OrdinalIgnoreCase))
                {
                    return new SignatureResult
                    {
                        Success = false,
                        Message = "Parol noto'g'ri yoki sertifikat formati xato - parol tekshiring"
                    };
                }

                return new SignatureResult
                {
                    Success = false,
                    Message = "Sertifikatni ochishda xatolik. Sertifikat PFX/P12 ekanligini va parol to'g'ri ekanligini tekshiring."
                };
            }

            if (!certificate.HasPrivateKey)
            {
                return new SignatureResult
                {
                    Success = false,
                    Message = "Sertifikatda private key mavjud emas. PFX fayl private key bilan export qiling."
                };
            }
             
            if (certificate.NotAfter < DateTime.Now)
            {
                return new SignatureResult
                {
                    Success = false,
                    Message = "Sertifikat muddati tugagan!"
                };
            }

            if (certificate.NotBefore > DateTime.Now)
            {
                return new SignatureResult
                {
                    Success = false,
                    Message = "Sertifikat hali amal qilmaydi!"
                };
            }
             
            var contentInfo = new ContentInfo(documentData);

            var signedCms = new SignedCms(contentInfo, detached: false);

            var cmsSigner = new CmsSigner(certificate)
            {
                IncludeOption = X509IncludeOption.WholeChain,
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1")
            };

            // Try to attach the concrete private key (RSA or ECDsa). If key algorithm is unsupported (e.g. GOST), provide a clear error.
            var rsaKey = certificate.GetRSAPrivateKey();
            var ecdsaKey = certificate.GetECDsaPrivateKey();
            AsymmetricAlgorithm privateKey = (AsymmetricAlgorithm?)rsaKey ?? (AsymmetricAlgorithm?)ecdsaKey;

            if (privateKey != null)
            {
                cmsSigner.PrivateKey = privateKey;
            }
            else
            {
                // Determine algorithm OID/name to give a helpful message
                var algOid = certificate.PublicKey?.Oid?.Value ?? certificate.SignatureAlgorithm?.Value ?? "";
                var algName = certificate.PublicKey?.Oid?.FriendlyName ?? certificate.SignatureAlgorithm?.FriendlyName ?? "";

                _logger.LogWarning("No supported private key found for certificate. OID={Oid} Name={Name}", algOid, algName);

                // Common GOST OIDs start with 1.2.643 - if detected, indicate unsupported algorithm
                if (!string.IsNullOrEmpty(algOid) && algOid.StartsWith("1.2.643"))
                {
                    return new SignatureResult
                    {
                        Success = false,
                        Message = "Sertifikat GOST algoritmida yoki HSM/tokenda saqlangan, serverda imzolash qo'llab-quvvatlanmaydi. Iltimos, tashqi E-Imzo ilovasi orqali imzo yuboring."
                    };
                }

                return new SignatureResult
                {
                    Success = false,
                    Message = "Sertifikat private keyi topilmadi yoki qo'llab-quvvatlanmaydigan algoritm. Tashqi ilova orqali imzolashni ishlating."
                };
            }
             
            var signingTime = new Pkcs9SigningTime(DateTime.Now);
            cmsSigner.SignedAttributes.Add(new AsnEncodedData(signingTime.Oid, signingTime.RawData));
             
            signedCms.ComputeSignature(cmsSigner);

            var signedData = signedCms.Encode();

            _logger.LogInformation("Hujjat muvaffaqiyatli imzolandi");

            return new SignatureResult
            {
                Success = true,
                Message = "Hujjat muvaffaqiyatli imzolandi!",
                SignedData = signedData,
                SignerInfo = ExtractSignerInfo(certificate)
            };
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Kriptografik xatolik");
            var msg = ex.Message;
            if (msg != null && msg.Contains("The specified network password is not correct", StringComparison.OrdinalIgnoreCase))
            {
                return new SignatureResult
                {
                    Success = false,
                    Message = "Parol noto'g'ri yoki sertifikat paroli mos kelmayapti. Iltimos parolni tekshiring."
                };
            }

            return new SignatureResult
            {
                Success = false,
                Message = $"Xatolik: {ex.Message}"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Imzolashda xatolik");
            return new SignatureResult
            {
                Success = false,
                Message = $"Xatolik: {ex.Message}"
            };
        }
    }

    public async Task<VerificationResult> VerifySignatureAsync(byte[] signedData)
    {
        try
        {
            _logger.LogInformation("Imzoni tekshirish boshlandi...");

            var signedCms = new SignedCms();
            signedCms.Decode(signedData);
             
            signedCms.CheckSignature(verifySignatureOnly: true);

            var signerInfo = signedCms.SignerInfos[0];
            var certificate = signerInfo.Certificate;
             
            var originalData = signedCms.ContentInfo.Content;
             
            DateTime? signingTime = null;
            foreach (var attr in signerInfo.SignedAttributes)
            {
                if (attr.Oid.Value == "1.2.840.113549.1.9.5")       
                {
                    var pkcs9 = new Pkcs9SigningTime(attr.Values[0].RawData);
                    signingTime = pkcs9.SigningTime;
                    break;
                }
            }

            _logger.LogInformation("Imzo to'g'ri va haqiqiy");

            return new VerificationResult
            {
                IsValid = true,
                Message = "Imzo to'g'ri va haqiqiy!",
                SignerInfo = ExtractSignerInfo(certificate),
                SigningTime = signingTime,
                OriginalData = originalData
            };
        }
        catch (CryptographicException ex)
        {
            _logger.LogWarning(ex, "Imzo noto'g'ri");
            return new VerificationResult
            {
                IsValid = false,
                Message = "Imzo noto'g'ri yoki buzilgan!"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Tekshirishda xatolik");
            return new VerificationResult
            {
                IsValid = false,
                Message = $"Xatolik: {ex.Message}"
            };
        }
    }

    public async Task<List<CertificateInfo>> GetInstalledCertificatesAsync()
    {
        var certificates = new List<CertificateInfo>();

        try
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            foreach (var cert in store.Certificates)
            {
                if (cert.HasPrivateKey)
                {
                    certificates.Add(new CertificateInfo
                    {
                        SubjectName = cert.Subject,
                        IssuerName = cert.Issuer,
                        SerialNumber = cert.SerialNumber,
                        ValidFrom = cert.NotBefore,
                        ValidTo = cert.NotAfter,
                        Thumbprint = cert.Thumbprint,
                        IsValid = cert.NotAfter > DateTime.Now && cert.NotBefore < DateTime.Now
                    });
                }
            }

            store.Close();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Sertifikatlarni yuklashda xatolik");
        }

        return certificates;
    }

    public async Task<SignerInfo> GetCertificateInfoAsync(byte[] certificateData, string password)
    {
        try
        {
            var keyStorageFlags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet;

            X509Certificate2 certificate = null;
            try
            {
                var primary = new X509Certificate2(certificateData, password, keyStorageFlags);
                if (primary.HasPrivateKey)
                {
                    certificate = primary;
                }
                else
                {
                    var collection = new X509Certificate2Collection();
                    collection.Import(certificateData, password, keyStorageFlags);
                    certificate = collection.OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey) ?? primary;
                }
            }
            catch
            {
                // Fallback: try without flags
                certificate = new X509Certificate2(certificateData, password);
            }

            return ExtractSignerInfo(certificate);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Sertifikat ma'lumotlarini olishda xatolik");
            return null;
        }
    }

    private SignerInfo ExtractSignerInfo(X509Certificate2 certificate)
    {
        var subjectParts = ParseDistinguishedName(certificate.Subject);

        return new SignerInfo
        {
            SubjectName = certificate.Subject,
            IssuerName = certificate.Issuer,
            SerialNumber = certificate.SerialNumber,
            ValidFrom = certificate.NotBefore,
            ValidTo = certificate.NotAfter,
            Thumbprint = certificate.Thumbprint,
            CommonName = subjectParts.ContainsKey("CN") ? subjectParts["CN"] : "",
            Organization = subjectParts.ContainsKey("O") ? subjectParts["O"] : "",
            Country = subjectParts.ContainsKey("C") ? subjectParts["C"] : ""
        };
    }

    private Dictionary<string, string> ParseDistinguishedName(string dn)
    {
        var result = new Dictionary<string, string>();
        var parts = dn.Split(',');

        foreach (var part in parts)
        {
            var keyValue = part.Trim().Split('=');
            if (keyValue.Length == 2)
            {
                result[keyValue[0].Trim()] = keyValue[1].Trim();
            }
        }

        return result;
    }
}
