namespace AuthEndpoints.Users;

/// <summary>
/// Represents all the options you can use to configure the User endpoints system.
/// </summary>
public class UserEndpointsOptions
{
    /// <summary>
    /// URL to your frontend email verification page.
    /// </summary>
    public string? EmailConfirmationUrl { get; set; }

    /// <summary>
    /// URL to your frontend password reset page.
    /// </summary>
    public string? PasswordResetUrl { get; set; }
}
