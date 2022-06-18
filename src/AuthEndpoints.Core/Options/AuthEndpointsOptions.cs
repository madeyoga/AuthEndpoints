using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

/// <summary>
/// Represents all the options you can use to configure the AuthEndpoints system.
/// </summary>
public class AuthEndpointsOptions
{
    public const string Key = "AuthEndpoints";

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
        ExpirationMinutes = 2880
    };

    /// <summary>
    /// Validation parameters used for verifying access jwts
    /// </summary>
    public TokenValidationParameters? AccessValidationParameters { get; set; }

    /// <summary>
    /// Validation parameters used for verifying refresh jwts
    /// </summary>
    public TokenValidationParameters? RefreshValidationParameters { get; set; }

    /// <summary>
    /// URL to your frontend email verification page.
    /// </summary>
    public string? EmailConfirmationUrl { get; set; }

    /// <summary>
    /// URL to your frontend password reset page.
    /// </summary>
    public string? PasswordResetUrl { get; set; }

    /// <summary>
    /// Email configuration used for sending reset password link or verification email link via email.
    /// </summary>
    public EmailOptions? EmailOptions { get; set; }
}
