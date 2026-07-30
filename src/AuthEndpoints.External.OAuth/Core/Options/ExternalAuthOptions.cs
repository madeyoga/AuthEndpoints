namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Options for external OAuth endpoints.
/// </summary>
public sealed class ExternalAuthOptions
{
    /// <summary>
    /// Optional sign-in scheme used by the default cookie completer.
    /// When null, <see cref="Microsoft.AspNetCore.Identity.SignInManager{TUser}"/> keeps its configured scheme
    /// (typically <c>Identity.Application</c>).
    /// </summary>
    public string? SignInScheme { get; set; }

    /// <summary>
    /// Whether the application cookie is persistent. Default: <c>true</c>.
    /// </summary>
    public bool IsPersistent { get; set; } = true;

    /// <summary>
    /// Fallback redirect when <c>returnUrl</c> is missing or not allowed. Must be a relative local path.
    /// Default: <c>/</c>.
    /// </summary>
    public string DefaultReturnUrl { get; set; } = "/";

    /// <summary>
    /// When true (default), create/link requires a verified email claim from the provider.
    /// </summary>
    public bool RequireVerifiedEmail { get; set; } = true;

    /// <summary>
    /// When true (default), an existing local user with the same verified email is linked to the external login.
    /// When false, matching email without an existing login link fails.
    /// </summary>
    public bool AutoLinkByEmail { get; set; } = true;

    /// <summary>
    /// Absolute origins allowed for <c>returnUrl</c> (e.g. <c>https://app.example.com</c>).
    /// Empty (default) means only relative local paths are accepted.
    /// </summary>
    public IList<string> AllowedReturnUrlOrigins { get; } = new List<string>();

    /// <summary>
    /// Relative path for OAuth error redirects (browser). Query includes <c>error</c> and <c>error_description</c>.
    /// Default: <c>/auth/external/error</c>.
    /// </summary>
    public string ErrorPath { get; set; } = "/auth/external/error";
}
