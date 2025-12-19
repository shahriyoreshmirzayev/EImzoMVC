namespace EImzoMVC.Models;

public class EImzoChallangeResultDto
{
    public string Challenge { get; set; } = "";
}

public class EImzoAuthDto
{
    public string SignData { get; set; } = "";
}

public class EImzoAuthResultDto
{
    public int Status { get; set; }
    public string Message { get; set; } = "";
}

public class EImzoTimeStampDto
{
    public string SignData { get; set; } = "";
}

public class SubjectInfoDto
{
    public string? Inn { get; set; }
    public string? Pinfl { get; set; }
}

public class TimestampedSignerDto
{
    public SubjectInfoDto SubjectName { get; set; } = new SubjectInfoDto();
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
}

public class EImzoTimeStampResultDto
{
    public int Status { get; set; }
    public string Message { get; set; } = "";
    public string Pkcs7b64 { get; set; } = "";
    public List<TimestampedSignerDto> TimestampedSignerList { get; set; } = new List<TimestampedSignerDto>();
}

public class EImzoVerifyDto
{
    public string SignData { get; set; } = "";
}


public class CertificateSubjectInfoDto
{
    public string? Inn { get; set; }
    public string? Pinfl { get; set; }
}

public class CertificateDto
{
    public CertificateSubjectInfoDto SubjectInfo { get; set; } = new CertificateSubjectInfoDto();
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
}

public class SignerCertificateDto
{
    public List<CertificateDto> Certificate { get; set; } = new List<CertificateDto>();
}

public class Pkcs7InfoDto
{
    public string DocumentBase64 { get; set; } = "";
    public List<SignerCertificateDto> Signers { get; set; } = new List<SignerCertificateDto>();
}

public class EImzoVerifyResultDto
{
    public int Status { get; set; }
    public string Message { get; set; } = "";
    public Pkcs7InfoDto Pkcs7Info { get; set; } = new Pkcs7InfoDto();
}

public class ESignInResponseModel
{
    public string? RequestId { get; set; }
    public int? UserId { get; set; }
    public bool IsPinfl { get; set; }
    public string? Pinfl { get; set; }
    public string? Inn { get; set; }
}

public class RemoteSignCallbackDto
{
    public string SignData { get; set; } = "";
    public string? Token { get; set; }
}
