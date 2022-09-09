using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt.Core;

public class SimpleJwtOptions
{
    public const string Key = "SimpleJwtOptions";

    public string Issuer { get; set; } = "webapi";
    public string Audience { get; set; } = "webapi";

    /// <summary>
    /// Signing options used for signing access jwts
    /// </summary>
    public JwtSigningOptions AccessSigningOptions { get; set; } = new JwtSigningOptions()
    {
        Algorithm = SecurityAlgorithms.HmacSha256,
        ExpirationMinutes = 120
    };

    /// <summary>
    /// Signing options used for signing refresh jwts
    /// </summary>
    public JwtSigningOptions RefreshSigningOptions { get; set; } = new JwtSigningOptions()
    {
        Algorithm = SecurityAlgorithms.HmacSha256,
        ExpirationMinutes = 1440
    };

    /// <summary>
    /// Validation parameters used for verifying access jwts
    /// </summary>
    public TokenValidationParameters? AccessValidationParameters { get; set; }

    /// <summary>
    /// Validation parameters used for verifying refresh jwts
    /// </summary>
    public TokenValidationParameters? RefreshValidationParameters { get; set; }
}
