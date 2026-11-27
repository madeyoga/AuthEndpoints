using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Every JWT setting: token signing and validation, and the refresh session.
/// Set them in the <c>AddJwt</c> or <c>AddJwtEndpoints</c> callback. They are fixed when that call runs, because the
/// signing key also configures JWT bearer validation, so a later <c>Configure&lt;SimpleJwtOptions&gt;</c> has no effect.
/// </summary>
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
    /// Where the refresh token is issued and accepted. Default: <see cref="RefreshTokenTransport.Cookie"/>.
    /// </summary>
    public RefreshTokenTransport RefreshTokenTransport { get; set; } = RefreshTokenTransport.Cookie;

    /// <summary>
    /// Lifetime of one refresh token from the moment it is issued.
    /// Default: 14 days. A successor expires at most this far ahead, and never later than
    /// <see cref="AbsoluteLifetime"/> from the original sign-in.
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Lifetime of a refresh-token family, measured from the original sign-in.
    /// Rotation cannot extend it. Default: 14 days, the same window as <see cref="RefreshTokenLifetime"/>,
    /// so refreshing does not keep a session alive past that cap.
    /// </summary>
    public TimeSpan AbsoluteLifetime { get; set; } = TimeSpan.FromDays(14);
}
