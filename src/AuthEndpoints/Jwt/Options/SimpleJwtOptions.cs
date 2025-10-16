using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Jwt;

public class SimpleJwtOptions
{
    public string Issuer { get; set; } = "Jwt";
    public string Audience { get; set; } = "JwtAudience";
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Signing options (symmetric by default, RSA/ECDSA/X509 optional).
    /// </summary>
    public SimpleJwtSigningOptions SigningOptions { get; set; } = new();

    /// <summary>
    /// Advanced override: fully custom TokenValidationParameters.
    /// </summary>
    public TokenValidationParameters? TokenValidationParameters { get; set; }
}
