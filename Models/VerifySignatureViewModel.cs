using System.ComponentModel.DataAnnotations;

namespace EImzoMVC;

public class VerifySignatureViewModel
{
    [Required(ErrorMessage = "Imzolangan faylni tanlang")]
    [Display(Name = "Imzolangan fayl (.p7s)")]
    public IFormFile SignedFile { get; set; }
}
