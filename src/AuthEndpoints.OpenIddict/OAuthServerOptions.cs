using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Settings for the OAuth 2.0 authorization server. Bind them from configuration or set them in code.
/// The defaults are the safe ones. Each opt-out is named <c>Disable…</c> or <c>Ignore…</c>.
/// </summary>
public sealed class OAuthServerOptions
{
    /// <summary>
    /// The public issuer URI, for example <c>https://auth.example.com/</c>. Required.
    /// Tokens, metadata, and the <c>iss</c> authorization response parameter use this value.
    /// It is never read from the request <c>Host</c> header.
    /// </summary>
    public Uri? Issuer { get; set; }

    /// <summary>
    /// The resource indicator (RFC 8707) stamped into access tokens as their audience when the client
    /// does not send <c>resource</c>. This host's token validation accepts only this audience. Required.
    /// Use an absolute URI, for example <c>https://api.example.com/</c>.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Other resource indicators a client may request. Tokens for them are not accepted by this host's
    /// own validation (only <see cref="Audience"/> is). Use this when other APIs validate the tokens.
    /// </summary>
    public IList<string> AdditionalResources { get; } = new List<string>();

    /// <summary>Scopes clients may request. <c>offline_access</c> is always registered.</summary>
    public IList<string> Scopes { get; } = new List<string>();

    /// <summary>Scopes granted when the authorize request has no <c>scope</c>. Must be in <see cref="Scopes"/>.</summary>
    public IList<string> DefaultScopes { get; } = new List<string>();

    /// <summary>
    /// Add <c>offline_access</c> when the client left it out, so the token endpoint returns a refresh token.
    /// Default <see langword="true"/>.
    /// </summary>
    public bool AlwaysIssueRefreshToken { get; set; } = true;

    /// <summary>
    /// The host's sign-in page. A signed-out authorize request is redirected here with the authorize URL
    /// (a relative path on this server) in <see cref="LoginReturnUrlParameter"/>. Absolute or rooted. Required.
    /// </summary>
    public string? LoginUrl { get; set; }

    /// <summary>Query parameter that carries the authorize URL to the sign-in page. Default <c>returnUrl</c>.</summary>
    public string LoginReturnUrlParameter { get; set; } = "returnUrl";

    /// <summary>
    /// The host's consent page. The authorize endpoint stores a pending request and redirects here with its id in
    /// <see cref="ConsentRequestParameter"/>. Absolute or rooted. Required.
    /// </summary>
    public string? ConsentUrl { get; set; }

    /// <summary>Query parameter that carries the pending request id to the consent page. Default <c>request</c>.</summary>
    public string ConsentRequestParameter { get; set; } = "request";

    /// <summary>
    /// Scheme that identifies the signed-in user at the authorize and consent endpoints.
    /// Default <see cref="IdentityConstants.ApplicationScheme"/> (the Identity cookie).
    /// </summary>
    public string AuthenticationScheme { get; set; } = IdentityConstants.ApplicationScheme;

    /// <summary>Claim on the signed-in principal that holds the user id. Default <see cref="ClaimTypes.NameIdentifier"/>.</summary>
    public string UserIdClaimType { get; set; } = ClaimTypes.NameIdentifier;

    /// <summary>Authorization code lifetime. Default 5 minutes.</summary>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Access token lifetime. Default 15 minutes.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Refresh token lifetime. Each refresh issues a new token and the old one stops working at once. Default 30 days.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>How long a pending consent request stays usable. Default 10 minutes.</summary>
    public TimeSpan ConsentLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Signing and encryption keys. One source is required.</summary>
    public OAuthServerCertificateOptions Certificates { get; } = new();

    /// <summary>Anonymous client registration (RFC 7591). Off by default.</summary>
    public OAuthDynamicRegistrationOptions DynamicRegistration { get; } = new();

    /// <summary>Protected resource metadata (RFC 9728) and the matching <c>WWW-Authenticate</c> challenge. Off by default.</summary>
    public OAuthProtectedResourceOptions ProtectedResource { get; } = new();

    /// <summary>Clients created or updated by <c>SeedOAuthClientsAsync</c>.</summary>
    public IList<OAuthClientDefinition> Clients { get; } = new List<OAuthClientDefinition>();

    /// <summary>How often the background cleanup runs. Zero or less turns it off. Default 1 hour.</summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Expired or revoked tokens and authorizations older than this are deleted by the cleanup. Default 14 days.</summary>
    public TimeSpan PruneAfter { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// On every code exchange and refresh, check that the approving user still exists, can sign in, is not locked out,
    /// and has the same security stamp. A failed check revokes the grant. Default <see langword="true"/>.
    /// </summary>
    public bool RevalidateUser { get; set; } = true;

    /// <summary>Allow plain HTTP. Only for local development behind no proxy. Default <see langword="false"/>.</summary>
    public bool DisableTransportSecurityRequirement { get; set; }

    /// <summary>
    /// Skip OpenIddict's check that the token request <c>resource</c> is a registered resource.
    /// The authorize endpoint still accepts only configured resources. Default <see langword="false"/>.
    /// </summary>
    public bool DisableResourceValidation { get; set; }

    /// <summary>Skip the per-client <c>rsrc:</c> permission check. Default <see langword="false"/>.</summary>
    public bool IgnoreResourcePermissions { get; set; }

    internal IEnumerable<string> AllResources()
        => (Audience is null ? [] : new[] { Audience }).Concat(AdditionalResources).Distinct(StringComparer.Ordinal);

    internal IEnumerable<string> AllScopes()
        => Scopes.Append(OAuthServerConstants.OfflineAccessScope).Distinct(StringComparer.Ordinal);
}

/// <summary>Where the server gets its signing and encryption keys.</summary>
public sealed class OAuthServerCertificateOptions
{
    /// <summary>
    /// Directory for a self-signed signing and encryption certificate pair. Created on first start and reused,
    /// so tokens survive a restart. Protect it like Data Protection keys and share it between instances.
    /// </summary>
    public string? Path { get; set; }

    /// <summary>Subject common name for generated certificates. Default <c>AuthEndpoints OAuth</c>.</summary>
    public string SubjectName { get; set; } = "AuthEndpoints OAuth";

    /// <summary>A signing certificate with a private key. Set it together with <see cref="EncryptionCertificate"/>.</summary>
    public X509Certificate2? SigningCertificate { get; set; }

    /// <summary>An encryption certificate with a private key. Set it together with <see cref="SigningCertificate"/>.</summary>
    public X509Certificate2? EncryptionCertificate { get; set; }

    /// <summary>In-memory keys that are lost on restart. Tests and local development only.</summary>
    public bool UseEphemeralKeys { get; set; }
}

/// <summary>Dynamic client registration (RFC 7591). Only public clients with PKCE can register.</summary>
public sealed class OAuthDynamicRegistrationOptions
{
    /// <summary>Map <c>POST /connect/register</c> and advertise it in metadata. Default <see langword="false"/>.</summary>
    public bool Enabled { get; set; }

    /// <summary>Registrations allowed per client IP address each minute. Default 10.</summary>
    public int PermitsPerMinute { get; set; } = 10;

    /// <summary>A registered client that no user approved is deleted after this age. Default 24 hours.</summary>
    public TimeSpan UnusedClientLifetime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Longest accepted <c>client_name</c>. Default 200.</summary>
    public int MaxClientNameLength { get; set; } = 200;

    /// <summary>Most redirect URIs one registration may list. Default 10.</summary>
    public int MaxRedirectUris { get; set; } = 10;
}

/// <summary>RFC 9728 protected resource metadata for <see cref="OAuthServerOptions.Audience"/>.</summary>
public sealed class OAuthProtectedResourceOptions
{
    /// <summary>Map <c>GET /.well-known/oauth-protected-resource</c>. Default <see langword="false"/>.</summary>
    public bool Enabled { get; set; }

    /// <summary>Human-readable <c>resource_name</c>. Optional.</summary>
    public string? ResourceName { get; set; }

    /// <summary>
    /// Path prefixes whose 401 responses get <c>WWW-Authenticate: Bearer resource_metadata="…"</c>
    /// from <c>UseOAuthResourceChallenge</c>. Empty means every path.
    /// </summary>
    public IList<string> ChallengePaths { get; } = new List<string>();
}

/// <summary>A client created by <c>SeedOAuthClientsAsync</c>.</summary>
public sealed class OAuthClientDefinition
{
    public string? ClientId { get; set; }

    public string? DisplayName { get; set; }

    /// <summary>Set to make a confidential client. Leave empty for a public client. Prefer a secret store over appsettings.</summary>
    public string? ClientSecret { get; set; }

    public IList<string> RedirectUris { get; } = new List<string>();

    /// <summary>Scopes this client may request. Empty means every configured scope.</summary>
    public IList<string> Scopes { get; } = new List<string>();

    /// <summary>Resources this client may request. Empty means every configured resource.</summary>
    public IList<string> Resources { get; } = new List<string>();
}
