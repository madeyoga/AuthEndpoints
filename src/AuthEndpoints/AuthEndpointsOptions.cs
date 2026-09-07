using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints;

/// <summary>
/// Options for the opinionated <c>AddAuthEndpoints</c> / <c>UseAuthEndpoints</c> / <c>MapAuthEndpoints</c> facade.
/// </summary>
public sealed class AuthEndpointsOptions
{
    /// <summary>
    /// Route prefix for Identity management plus the configured sign-in stack.
    /// Default: <c>/identity</c>.
    /// </summary>
    public string IdentityPath { get; set; } = "/identity";

    /// <summary>
    /// Sign-in module mapped under <see cref="IdentityPath"/>.
    /// Default: <see cref="AuthEndpointsSignIn.Cookie"/>.
    /// Pass <see cref="AuthEndpointsSignIn.IdentityBearer"/> to
    /// <c>AddAuthEndpoints</c> to map Identity bearer login instead of cookie login.
    /// </summary>
    public AuthEndpointsSignIn SignIn { get; set; } = AuthEndpointsSignIn.Cookie;

    /// <summary>Route prefix for passkey endpoints. Default: <c>/account</c>.</summary>
    public string PasskeyPath { get; set; } = "/account";

    /// <summary>When true, Identity requires a confirmed account before sign-in. Default: <c>true</c>.</summary>
    public bool RequireConfirmedAccount { get; set; } = true;

    /// <summary>Passkey (WebAuthn) settings for the default bundle.</summary>
    public AuthEndpointsPasskeyOptions Passkeys { get; set; } = new();

    /// <summary>SPA redirect after browser GET confirm-email.</summary>
    public AuthEndpointsEmailConfirmationOptions EmailConfirmation { get; set; } = new();

    /// <summary>Optional JWT settings. Disabled by default; enable for facade JWT mapping.</summary>
    public AuthEndpointsJwtOptions Jwt { get; set; } = new();

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

/// <summary>Email confirmation redirect settings for SPA hosts.</summary>
public sealed class AuthEndpointsEmailConfirmationOptions
{
    /// <summary>
    /// Frontend URI after <c>GET</c> confirm-email (absolute <c>https://</c>, or a rooted path).
    /// Empty or null keeps the plain-text / 401 response.
    /// </summary>
    public string? ConfirmEmailRedirectUri { get; set; }

    /// <summary>
    /// Origins such as <c>https://app.example.com</c> allowed for an absolute <see cref="ConfirmEmailRedirectUri"/>.
    /// A rooted path does not need an entry.
    /// </summary>
    public IList<string> AllowedRedirectOrigins { get; set; } = new List<string>();
}

/// <summary>JWT-related options for the opinionated facade.</summary>
public sealed class AuthEndpointsJwtOptions
{
    /// <summary>When true, registers and maps JWT endpoints. Default: <c>false</c>.</summary>
    public bool Enabled { get; set; }

    /// <summary>Route prefix for JWT endpoints. Default: <c>/auth</c>.</summary>
    public string Path { get; set; } = "/auth";

    /// <summary>Optional JWT options customization (signing key, issuer, audience, etc.).</summary>
    public Action<SimpleJwtOptions>? Configure { get; set; }
}
