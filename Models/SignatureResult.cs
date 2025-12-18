namespace EImzoMVC;

public class SignatureResult
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public string FileName { get; set; }
    public byte[] SignedData { get; set; }
    public SignerInfo SignerInfo { get; set; }
}
