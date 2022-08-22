namespace AuthEndpoints.Core;

/// <summary>
/// Represents all the options you can use to configure the AuthEndpoints system.
/// </summary>
public class AuthEndpointsOptions
{
    public const string Key = "AuthEndpoints";

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
