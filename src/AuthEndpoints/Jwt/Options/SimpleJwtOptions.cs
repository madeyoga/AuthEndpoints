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

    /// <summary>
    /// Refresh-token transport copied onto <see cref="JwtSessionOptions.RefreshTokenTransport"/> by <c>AddPasswordAuth</c>.
    /// <c>AddJwtEndpoints</c> does not read this property. Compose hosts set <see cref="JwtSessionOptions"/> instead.
    /// Default: <see cref="RefreshTokenTransport.Cookie"/>.
    /// </summary>
    public RefreshTokenTransport RefreshTokenTransport { get; set; } = RefreshTokenTransport.Cookie;
}
