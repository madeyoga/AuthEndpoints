using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints;

public class AsymmetricJwtOptions
{
    public string? PrivateKey { get; set; }
    public string? PublicKey { get; set; }
    [Required]
    public string? Issuer { get; set; }
    [Required]
    public string? Audience { get; set; }
    public int AccessTokenExpirationMinutes { get; set; } = 120;
    public int RefreshTokenExpirationMinutes { get; set; } = 2880;
}
