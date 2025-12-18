using System;

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

public class EImzoTimeStampResultDto
{
    public int Status { get; set; }
    public string Message { get; set; } = "";
}

public class EImzoVerifyDto
{
    public string SignData { get; set; } = "";
}

public class EImzoVerifyResultDto
{
    public int Status { get; set; }
    public string Message { get; set; } = "";
}

public class RemoteSignCallbackDto
{
    public string SignData { get; set; } = "";
    public string? Token { get; set; }
}
