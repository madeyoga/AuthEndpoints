namespace AuthEndpoints.Core.Contracts;

/// <summary>
/// the dto used for verify request
/// </summary>
public class VerifyRequest
{
    public string? Token { get; set; }
}
