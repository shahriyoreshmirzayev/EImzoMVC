namespace EImzoMVC;

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
