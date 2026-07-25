using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints;

/// <summary>
/// Options for the opinionated <c>AddAuthEndpoints</c> / <c>UseAuthEndpoints</c> / <c>MapAuthEndpoints</c> facade.
/// </summary>
public sealed class AuthEndpointsOptions
{
    /// <summary>Route prefix for cookie Identity endpoints. Default: <c>/identity</c>.</summary>
    public string IdentityPath { get; set; } = "/identity";

    /// <summary>Route prefix for passkey endpoints. Default: <c>/account</c>.</summary>
    public string PasskeyPath { get; set; } = "/account";

    /// <summary>When true, Identity requires a confirmed account before sign-in. Default: <c>true</c>.</summary>
    public bool RequireConfirmedAccount { get; set; } = true;

    /// <summary>Passkey (WebAuthn) settings for the default bundle.</summary>
    public AuthEndpointsPasskeyOptions Passkeys { get; set; } = new();

    /// <summary>Optional Identity options customization applied after secure defaults.</summary>
    public Action<IdentityOptions>? ConfigureIdentity { get; set; }

    /// <summary>Optional passkey options customization applied after <see cref="AuthEndpointsPasskeyOptions.ServerDomain"/>.</summary>
    public Action<IdentityPasskeyOptions>? ConfigurePasskeys { get; set; }

    /// <summary>
    /// When true (default), Production hosts must register a real <c>IEmailSender&lt;TUser&gt;</c>
    /// (not the Identity no-op). Development is not checked.
    /// </summary>
    public bool RequireEmailSenderInProduction { get; set; } = true;
}

/// <summary>Passkey-related options for the opinionated facade.</summary>
public sealed class AuthEndpointsPasskeyOptions
{
    /// <summary>When false, passkey DI and mapping are skipped. Default: <c>true</c>.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// WebAuthn relying-party domain (e.g. <c>example.com</c>).
    /// Required in Production when <see cref="Enabled"/> is true.
    /// </summary>
    public string? ServerDomain { get; set; }
}
