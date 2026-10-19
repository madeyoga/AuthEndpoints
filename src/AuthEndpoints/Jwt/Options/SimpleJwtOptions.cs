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
    /// Refresh-token transport applied to <see cref="JwtSessionOptions.RefreshTokenTransport"/> by <c>AddJwtEndpoints</c>
    /// when this value is not <see cref="RefreshTokenTransport.Cookie"/>.
    /// <c>AddPasswordAuth</c> and the 3.4.1 facade pass their JWT callback through <c>AddJwtEndpoints</c>, so a non-default value is honoured there too.
    /// The default <see cref="RefreshTokenTransport.Cookie"/> matches 3.4.1 and leaves an earlier
    /// <c>Configure&lt;JwtSessionOptions&gt;</c> in place.
    /// A <c>Configure&lt;JwtSessionOptions&gt;</c> registered after <c>AddJwtEndpoints</c> replaces it.
    /// </summary>
    public RefreshTokenTransport RefreshTokenTransport { get; set; } = RefreshTokenTransport.Cookie;
}
