namespace EImzoMVC;

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
