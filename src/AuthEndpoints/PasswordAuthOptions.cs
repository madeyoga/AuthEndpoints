using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints;

/// <summary>
/// Options for the password facade <c>AddPasswordAuth</c> / <c>MapPasswordAuth</c>.
/// One call registers one session. Cookie is the default. Jwt is allowed.
/// Identity bearer stays on <c>AddAuthEndpoints</c>.
/// </summary>
public sealed class PasswordAuthOptions
{
    /// <summary>
    /// Session the facade maps. Default: <see cref="AuthEndpointsSession.Cookie"/>.
    /// <see cref="AuthEndpointsSession.Jwt"/> is allowed.
    /// <see cref="AuthEndpointsSession.IdentityBearer"/> fails startup validation.
    /// </summary>
    public AuthEndpointsSession Session { get; set; } = AuthEndpointsSession.Cookie;

    /// <summary>
    /// Prefix for every route this facade maps. Default: <c>/auth</c>.
    /// </summary>
    public string Path { get; set; } = "/auth";

    /// <summary>
    /// When true, Identity requires a confirmed account before sign-in. Default: <c>true</c>.
    /// <see cref="ConfigureIdentity"/> runs after this value is applied and can replace it.
    /// </summary>
    public bool RequireConfirmedAccount { get; set; } = true;

    /// <summary>
    /// Passkey sign-in and management. Mapped when <see cref="PasskeyScenarioOptions.ServerDomain"/> is set.
    /// </summary>
    public PasskeyScenarioOptions Passkeys { get; } = new();

    /// <summary>
    /// SPA redirect after browser <c>GET</c> confirm-email.
    /// Copied onto <see cref="AuthEndpointsOptions.EmailConfirmation"/>, which the confirm-email handler reads.
    /// </summary>
    public EmailConfirmationOptions EmailConfirmation { get; } = new();

    /// <summary>
    /// JWT signing configuration. Required when <see cref="Session"/> is <see cref="AuthEndpointsSession.Jwt"/>.
    /// <see cref="SimpleJwtOptions.RefreshTokenTransport"/> is applied by <c>AddJwtEndpoints</c>.
    /// </summary>
    public Action<SimpleJwtOptions>? Jwt { get; set; }

    /// <summary>
    /// Optional Identity options customization applied after <see cref="RequireConfirmedAccount"/>.
    /// </summary>
    public Action<IdentityOptions>? ConfigureIdentity { get; set; }

    /// <summary>
    /// When true (default), Production hosts must register a real <c>IEmailSender&lt;TUser&gt;</c>
    /// (not the Identity no-op). Development is not checked.
    /// </summary>
    public bool RequireEmailSenderInProduction { get; set; } = true;
}

/// <summary>
/// Passkey settings for <see cref="PasswordAuthOptions"/>.
/// Passkey routes are included only when <see cref="ServerDomain"/> is non-whitespace.
/// </summary>
public sealed class PasskeyScenarioOptions
{
    /// <summary>
    /// WebAuthn relying-party domain (for example <c>example.com</c>).
    /// When set, the facade maps passkey sign-in and management.
    /// </summary>
    public string? ServerDomain { get; set; }
}

/// <summary>
/// Email confirmation redirect settings for <see cref="PasswordAuthOptions"/>.
/// </summary>
public sealed class EmailConfirmationOptions
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
