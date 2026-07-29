namespace AuthEndpoints.External;

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
    /// Fallback redirect when <c>returnUrl</c> is missing or not local. Default: <c>/</c>.
    /// </summary>
    public string DefaultReturnUrl { get; set; } = "/";
}
