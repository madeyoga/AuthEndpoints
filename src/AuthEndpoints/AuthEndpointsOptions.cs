using AuthEndpoints.EmailCode;
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

    public AuthEndpointsPasskeyOptions Passkeys { get; set; } = new();

    /// <summary>SPA redirect after browser GET confirm-email.</summary>
    public AuthEndpointsEmailConfirmationOptions EmailConfirmation { get; set; } = new();

    /// <summary>Optional JWT settings. Disabled by default; enable for facade JWT mapping.</summary>
    public AuthEndpointsJwtOptions Jwt { get; set; } = new();

    /// <summary>Optional emailed-code sign-in. Disabled by default.</summary>
    public AuthEndpointsEmailCodeOptions EmailCode { get; set; } = new();

    /// <summary>
    /// Step-up ReAuth cookie and <c>reauthToken</c> lifetime.
    /// Default: 5 minutes, non-persistent, no sliding expiration.
    /// </summary>
    public AuthEndpointsReAuthOptions ReAuth { get; } = new();

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

public sealed class AuthEndpointsJwtOptions
{
    /// <summary>When true, registers and maps JWT endpoints. Default: <c>false</c>.</summary>
    public bool Enabled { get; set; }

    /// <summary>Route prefix for JWT endpoints. Default: <c>/auth</c>.</summary>
    public string Path { get; set; } = "/auth";

    public Action<SimpleJwtOptions>? Configure { get; set; }
}

public sealed class AuthEndpointsEmailCodeOptions
{
    /// <summary>When true, registers and maps email-code sign-in. Default: <c>false</c>.</summary>
    public bool Enabled { get; set; }

    public Action<EmailCodeOptions>? Configure { get; set; }
}

/// <summary>
/// Lifetime for the ReAuth cookie and header <c>reauthToken</c>.
/// Both use this value for the same confirm. The cookie is not persistent
/// and does not slide. Valid range: 1 minute through 60 minutes.
/// </summary>
public sealed class AuthEndpointsReAuthOptions
{
    /// <summary>
    /// How long a successful <c>confirmIdentity</c> stays valid.
    /// Default: 5 minutes. Applies to cookie <c>ExpireTimeSpan</c>,
    /// ticket <c>ExpiresUtc</c>, and <c>reauthToken</c> expiry.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Step-up with a fresh sign-in at an external provider the account has linked.
    /// On by default when external sign-in endpoints are registered.
    /// </summary>
    public ExternalReAuthOptions External { get; } = new();
}

/// <summary>
/// Controls step-up with a fresh external provider sign-in.
/// External step-up proves the user controls the provider account and its session right now.
/// It is weaker than a password or passkey, and some providers ignore requests for a fresh sign-in.
/// </summary>
public sealed class ExternalReAuthOptions
{
    /// <summary>When false, no provider can be used for step-up. Default: <c>true</c>.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Provider schemes (for example <c>GitHub</c>) that can't be used for step-up.
    /// Scheme names are compared case-sensitively.
    /// </summary>
    public ISet<string> DisabledProviders { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// How long the user has to finish the provider sign-in after starting step-up. Default: 5 minutes.
    /// </summary>
    public TimeSpan RequestLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Returns true when <paramref name="scheme"/> may be used for step-up.</summary>
    public bool IsAllowed(string scheme) => Enabled && !DisabledProviders.Contains(scheme);
}
