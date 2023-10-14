using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// The dto used for login request
/// </summary>
public class SimpleJwtLoginRequest
{
    [Required]
    public string? Username { get; set; }

    [Required]
    public string? Password { get; set; }

    public string? TwoFactorCode { get; set; }

    public string? TwoFactorRecoveryCode { get; set; }
}
