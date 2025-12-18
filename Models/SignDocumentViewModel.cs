using System.ComponentModel.DataAnnotations;

namespace EImzoMVC;

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
