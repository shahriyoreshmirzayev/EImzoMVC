using System.ComponentModel.DataAnnotations;

namespace EImzoMVC.Models;

public class SignDocumentViewModel
{
    [Required(ErrorMessage = "Hujjat faylini tanlang")]
    [Display(Name = "Hujjat fayli")]
    public IFormFile DocumentFile { get; set; }

    [Required(ErrorMessage = "Sertifikat faylini tanlang")]
    [Display(Name = "Sertifikat fayli (PFX/P12)")]
    public IFormFile CertificateFile { get; set; }

    [Required(ErrorMessage = "Parolni kiriting")]
    [DataType(DataType.Password)]
    [Display(Name = "Sertifikat paroli")]
    public string Password { get; set; }
}

public class VerifySignatureViewModel
{
    [Required(ErrorMessage = "Imzolangan faylni tanlang")]
    [Display(Name = "Imzolangan fayl (.p7s)")]
    public IFormFile SignedFile { get; set; }
}

public class SignatureResult
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public string FileName { get; set; }
    public byte[] SignedData { get; set; }
    public SignerInfo SignerInfo { get; set; }
}

public class VerificationResult
{
    public bool IsValid { get; set; }
    public string Message { get; set; }
    public SignerInfo SignerInfo { get; set; }
    public DateTime? SigningTime { get; set; }
    public byte[] OriginalData { get; set; }
}

public class SignerInfo
{
    public string SubjectName { get; set; }
    public string IssuerName { get; set; }
    public string SerialNumber { get; set; }
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public string Thumbprint { get; set; }
    public string CommonName { get; set; }
    public string Organization { get; set; }
    public string Country { get; set; }
}

public class CertificateListViewModel
{
    public List<CertificateInfo> Certificates { get; set; }
}

public class CertificateInfo
{
    public string SubjectName { get; set; }
    public string IssuerName { get; set; }
    public string SerialNumber { get; set; }
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public string Thumbprint { get; set; }
    public bool IsValid { get; set; }
}
