namespace EImzoMVC;

public interface ISignatureService
{
    Task<SignatureResult> SignDocumentAsync(byte[] documentData, byte[] certificateData, string password);
    Task<VerificationResult> VerifySignatureAsync(byte[] signedData);
    Task<List<CertificateInfo>> GetInstalledCertificatesAsync();
    Task<SignerInfo> GetCertificateInfoAsync(byte[] certificateData, string password);
}
