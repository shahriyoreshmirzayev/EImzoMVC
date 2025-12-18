namespace EImzoMVC;

public class VerificationResult
{
    public bool IsValid { get; set; }
    public string Message { get; set; }
    public SignerInfo SignerInfo { get; set; }
    public DateTime? SigningTime { get; set; }
    public byte[] OriginalData { get; set; }
}
