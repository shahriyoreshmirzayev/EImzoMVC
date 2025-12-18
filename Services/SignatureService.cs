using EImzoMVC.Models;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SignerInfo = EImzoMVC.Models.SignerInfo;

namespace EImzoMVC.Services
{
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

                // Sertifikatni yuklash
                var certificate = new X509Certificate2(certificateData, password,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

                // Sertifikatni tekshirish
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

                // ContentInfo yaratish
                var contentInfo = new ContentInfo(documentData);

                // SignedCms obyekti
                var signedCms = new SignedCms(contentInfo, detached: false);

                // CmsSigner sozlash
                var cmsSigner = new CmsSigner(certificate)
                {
                    IncludeOption = X509IncludeOption.WholeChain,
                    DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") // SHA-256
                };

                // Imzolash vaqtini qo'shish
                var signingTime = new Pkcs9SigningTime(DateTime.Now);
                cmsSigner.SignedAttributes.Add(new AsnEncodedData(signingTime.Oid, signingTime.RawData));

                // Imzolash
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
                return new SignatureResult
                {
                    Success = false,
                    Message = $"Xatolik: Parol noto'g'ri yoki sertifikat formati xato - {ex.Message}"
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

                // Imzoni tekshirish
                signedCms.CheckSignature(verifySignatureOnly: true);

                var signerInfo = signedCms.SignerInfos[0];
                var certificate = signerInfo.Certificate;

                // Asl ma'lumotni olish
                var originalData = signedCms.ContentInfo.Content;

                // Imzolash vaqtini olish
                DateTime? signingTime = null;
                foreach (var attr in signerInfo.SignedAttributes)
                {
                    if (attr.Oid.Value == "1.2.840.113549.1.9.5") // signingTime
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
                var certificate = new X509Certificate2(certificateData, password);
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
}
