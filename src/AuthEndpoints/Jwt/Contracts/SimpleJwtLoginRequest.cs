namespace AuthEndpoints.Jwt;

/// <summary>
/// The dto used for login request
/// </summary>
public class SimpleJwtLoginRequest
{
    public required string Email { get; set; }

    public required string Password { get; set; }

    public string? TwoFactorCode { get; set; }

    public string? TwoFactorRecoveryCode { get; set; }
}
