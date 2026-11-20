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
    /// does not send <c>resource</c>. This host's token validation always accepts this audience, and by default
    /// only this one (see <see cref="AcceptedAudiences"/>). Required.
    /// Use an absolute URI, for example <c>https://api.example.com/</c>.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Other resource indicators a client may request. Tokens for them are not accepted by this host's
    /// own validation unless they are also in <see cref="AcceptedAudiences"/>. Use this when other APIs validate the tokens.
    /// </summary>
    public IList<string> AdditionalResources { get; } = new List<string>();

    /// <summary>
    /// Entries of <see cref="AdditionalResources"/> that this host's own token validation also accepts, for a host
    /// that serves more than one resource itself. Each must be a configured resource. <see cref="Audience"/> is always
    /// accepted. Empty (the default) accepts only <see cref="Audience"/>. Once this has entries, a token for any of them
    /// passes <c>ValidationScheme</c>, so check the audience on each route, for example with
    /// <c>RequireOAuthAudience</c>, or a token meant for one resource can call another.
    /// </summary>
    public IList<string> AcceptedAudiences { get; } = new List<string>();

    /// <summary>
    /// Scopes clients may request. <c>offline_access</c> is always registered. Add <c>openid</c> to turn on
    /// OpenID Connect (ID tokens, userinfo, logout), and <c>email</c> to release the user's email in them.
    /// </summary>
    public IList<string> Scopes { get; } = new List<string>();

    /// <summary>
    /// How the consent card describes scopes to a person: a display name and a description, optionally per culture.
    /// Each entry names a scope in <see cref="Scopes"/>, or <c>offline_access</c>. A scope without an entry is shown by its name.
    /// </summary>
    public IList<OAuthScopeDefinition> ScopeDefinitions { get; } = new List<OAuthScopeDefinition>();

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
    /// The host's sign-out confirmation page, for OpenID Connect logout. A logout request for a signed-in user that
    /// does not carry an <c>id_token_hint</c> issued to that user is redirected here, with the logout URL (a relative path
    /// on this server) in <see cref="LoginReturnUrlParameter"/>. The page signs the user out and sends the browser back.
    /// Absolute or rooted. Optional: without it, such a request is refused and the user stays signed in.
    /// </summary>
    public string? LogoutUrl { get; set; }

    /// <summary>
    /// Scheme that identifies the signed-in user at the authorize and consent endpoints.
    /// Default <see cref="IdentityConstants.ApplicationScheme"/> (the Identity cookie).
    /// </summary>
    public string AuthenticationScheme { get; set; } = IdentityConstants.ApplicationScheme;

    /// <summary>
    /// When a request carries <c>Authorization: Bearer</c>, make the Identity application cookie (and
    /// <see cref="AuthenticationScheme"/>) answer <c>401</c> instead of redirecting to the login page and <c>403</c> instead of
    /// redirecting to the access-denied page. A token caller refused on a route that also reads the cookie then gets a status
    /// code it can act on. Requests without the header, such as browser navigation, keep the cookie's own behavior, and the
    /// host's cookie events are still called for them. An app that sets <c>EventsType</c> keeps it: its events are resolved
    /// per request as before. Default <see langword="true"/>.
    /// </summary>
    public bool BearerRequestsSkipCookieRedirects { get; set; } = true;

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

    /// <summary>
    /// Clients that identify themselves with an <c>https</c> URL as <c>client_id</c>, which this server fetches to read
    /// their metadata (OAuth Client ID Metadata Document). Off by default.
    /// </summary>
    public OAuthClientMetadataDocumentOptions ClientMetadataDocuments { get; } = new();

    /// <summary>OAuth clients that signed-in users register and own (<c>MapOAuthDeveloperAppEndpoints</c>).</summary>
    public OAuthDeveloperAppOptions DeveloperApps { get; } = new();

    /// <summary>Protected resource metadata (RFC 9728) and the matching <c>WWW-Authenticate</c> challenge. Off by default.</summary>
    public OAuthProtectedResourceOptions ProtectedResource { get; } = new();

    /// <summary>
    /// Claims about the approving user that access tokens can carry, so existing role checks and user id lookups work for
    /// token callers. Off by default.
    /// </summary>
    public OAuthAccessTokenClaimOptions AccessTokenClaims { get; } = new();

    /// <summary>
    /// Rate limit for <c>/connect/token</c> and <c>/connect/revoke</c>, per endpoint, client id, and IP address. A rejected
    /// request gets <c>429</c> with the OAuth error <c>temporarily_unavailable</c> and <c>Retry-After</c>. Off by default.
    /// </summary>
    public OAuthTokenRateLimitOptions TokenRateLimit { get; } = new();

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

    /// <summary>
    /// Record when each grant was last used: at the code exchange and at a refresh, the time is written to the OpenIddict
    /// authorization (<see cref="OAuthServerConstants.AuthorizationLastUsedProperty"/>) when the stored time is older than
    /// <see cref="LastUsedInterval"/>. The connected apps list shows it. Default <see langword="false"/>.
    /// </summary>
    public bool RecordLastUsed { get; set; }

    /// <summary>
    /// With <see cref="RecordLastUsed"/>, the least time between two writes of the same grant's last-used time, so a client
    /// that refreshes often does not write on every refresh. Zero writes on every code exchange and refresh. Default 1 hour.
    /// </summary>
    public TimeSpan LastUsedInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Allow plain HTTP. Only for local development behind no proxy. Default <see langword="false"/>.</summary>
    public bool DisableTransportSecurityRequirement { get; set; }

    /// <summary>
    /// Skip OpenIddict's check that the token request <c>resource</c> is a registered resource.
    /// The authorize endpoint still accepts only configured resources. Default <see langword="false"/>.
    /// </summary>
    public bool DisableResourceValidation { get; set; }

    /// <summary>Skip the per-client <c>rsrc:</c> permission check. Default <see langword="false"/>.</summary>
    public bool IgnoreResourcePermissions { get; set; }

    /// <summary>
    /// Path prefixes, such as <c>/hubs</c>, where this host also reads an access token from the <c>access_token</c>
    /// query parameter. Use it for SignalR and WebSockets, where a browser cannot set the <c>Authorization</c> header.
    /// Prefixes match whole path segments (<c>/hubs</c> matches <c>/hubs/chat</c> but not <c>/hubsevil</c>) and are
    /// relative to <c>PathBase</c>. Each must start with <c>/</c>. Empty (the default) reads tokens only from
    /// <c>Authorization: Bearer</c>; the form body is never read. A token in a URL can end up in logs and proxies,
    /// so list only the paths that need it.
    /// </summary>
    public IList<string> QueryStringTokenPaths { get; } = new List<string>();

    internal IEnumerable<string> AllResources()
        => (Audience is null ? [] : new[] { Audience }).Concat(AdditionalResources).Distinct(StringComparer.Ordinal);

    /// <summary>The audiences this host's token validation accepts: <see cref="Audience"/> and <see cref="AcceptedAudiences"/>.</summary>
    internal IEnumerable<string> ValidationAudiences()
        => (Audience is null ? [] : new[] { Audience }).Concat(AcceptedAudiences).Distinct(StringComparer.Ordinal);

    /// <summary>OpenID Connect is on when the host registers the <c>openid</c> scope.</summary>
    internal bool OpenIdConnectEnabled => Scopes.Contains(OAuthServerConstants.OpenIdScope, StringComparer.Ordinal);

    internal IEnumerable<string> AllScopes()
        => Scopes.Append(OAuthServerConstants.OfflineAccessScope).Distinct(StringComparer.Ordinal);

    /// <summary>The scopes a dynamically registered client may hold: <see cref="OAuthDynamicRegistrationOptions.AllowedScopes"/>, or all of <see cref="Scopes"/>.</summary>
    internal IReadOnlyList<string> DynamicRegistrationScopes()
        => DynamicRegistration.AllowedScopes.Count == 0
            ? Scopes.Distinct(StringComparer.Ordinal).ToList()
            : DynamicRegistration.AllowedScopes.Where(scope => scope != OAuthServerConstants.OfflineAccessScope).Distinct(StringComparer.Ordinal).ToList();

    /// <summary>Whether a dynamically registered client may request <paramref name="scope"/>.</summary>
    internal bool AllowsDynamicRegistrationScope(string scope)
        => scope == OAuthServerConstants.OfflineAccessScope
            || DynamicRegistration.AllowedScopes.Count == 0
            || DynamicRegistration.AllowedScopes.Contains(scope, StringComparer.Ordinal);
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

    /// <summary>
    /// The scopes a dynamically registered client may request. Each must be in <see cref="OAuthServerOptions.Scopes"/>.
    /// Empty (the default) allows all of them. List the third-party scopes here to keep first-party scopes,
    /// such as one that acts as the user's whole account, to <see cref="OAuthServerOptions.Clients"/> and developer apps.
    /// <c>offline_access</c> is always allowed. Clients registered earlier are held to this list too, at
    /// <c>/connect/authorize</c>. Add <c>openid</c> to let them use OpenID Connect.
    /// </summary>
    public IList<string> AllowedScopes { get; } = new List<string>();
}

/// <summary>
/// Client ID metadata documents (draft-ietf-oauth-client-id-metadata-document), the client identification method the MCP
/// authorization spec prefers. A client sends an <c>https</c> URL as its <c>client_id</c>; <c>/connect/authorize</c> fetches
/// that URL, checks the JSON document it returns, and stores the client in OpenIddict's application store. Only public
/// clients with PKCE are accepted, held to the same redirect URI rules and
/// <see cref="OAuthDynamicRegistrationOptions.AllowedScopes"/> as dynamically registered clients.
/// </summary>
public sealed class OAuthClientMetadataDocumentOptions
{
    /// <summary>
    /// Accept <c>https</c> URLs as client ids and advertise <c>client_id_metadata_document_supported</c> in the authorization
    /// server metadata. Default <see langword="false"/>.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>How long one fetch may take, connection included. Default 5 seconds.</summary>
    public TimeSpan FetchTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Largest document read, in bytes. A larger one is refused. Default 5120 (5 KB, as the draft recommends).</summary>
    public int MaxDocumentBytes { get; set; } = 5 * 1024;

    /// <summary>
    /// Shortest time a fetched document is reused before it is fetched again. Used when the response has no
    /// <c>Cache-Control: max-age</c>, or asks for less, including <c>no-cache</c> and <c>no-store</c>. Default 5 minutes.
    /// </summary>
    public TimeSpan MinCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Longest time a fetched document is reused, whatever its <c>Cache-Control</c> says. Default 24 hours.</summary>
    public TimeSpan MaxCacheDuration { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Document fetches that authorize requests from one IP address may cause each minute. Reusing a stored document does
    /// not count. Default 20.
    /// </summary>
    public int FetchesPerMinute { get; set; } = 20;

    /// <summary>
    /// Hosts whose documents are accepted, such as <c>client.example.com</c>, or <c>*.example.com</c> for any subdomain
    /// (not <c>example.com</c> itself). Case-insensitive. Empty (the default) accepts any public host not in
    /// <see cref="DeniedHosts"/>.
    /// </summary>
    public IList<string> AllowedHosts { get; } = new List<string>();

    /// <summary>Hosts whose documents are refused, in the same form as <see cref="AllowedHosts"/>. Checked first.</summary>
    public IList<string> DeniedHosts { get; } = new List<string>();
}

/// <summary>Limits for developer apps, the OAuth clients that signed-in users register and own.</summary>
public sealed class OAuthDeveloperAppOptions
{
    /// <summary>
    /// New apps start as <see cref="OAuthDeveloperAppStatus.PendingApproval"/> and cannot sign users in
    /// until <c>IOAuthDeveloperAppService.SetStatusAsync</c> makes them active. Default <see langword="false"/>.
    /// </summary>
    public bool RequireApproval { get; set; }

    /// <summary>Most apps one user may own. Default 10.</summary>
    public int MaxAppsPerUser { get; set; } = 10;

    /// <summary>Most redirect URIs one app may list. Default 10.</summary>
    public int MaxRedirectUris { get; set; } = 10;
}

/// <summary>
/// Claims about the approving user added to each access token at the token endpoint (code exchange and refresh).
/// They go to the access token only, never to the authorization code, the refresh token, or the ID token, so every
/// new access token reads them again. They are added only when the token's <c>sub</c> is the approving user: a principal
/// factory that issues tokens for another subject gets neither.
/// </summary>
public sealed class OAuthAccessTokenClaimOptions
{
    /// <summary>
    /// Add the approving user's Identity roles as <c>role</c> claims, the role claim type of identities that
    /// <c>ValidationScheme</c> creates, so <c>IsInRole</c> and <c>RequireRole</c> work for token callers. Roles are read
    /// again at every refresh: a role change reaches the client within one access token lifetime. Needs Identity roles
    /// (<c>AddRoles&lt;TRole&gt;()</c>). Default <see langword="false"/>.
    /// </summary>
    public bool Roles { get; set; }

    /// <summary>
    /// Add <see cref="ClaimTypes.NameIdentifier"/>, <see cref="OAuthServerOptions.UserIdClaimType"/>, and
    /// <c>IdentityOptions.ClaimsIdentity.UserIdClaimType</c>, each set to <c>sub</c>, so <c>UserManager.GetUserId</c> and code
    /// written for cookie users find the user id. Default <see langword="false"/>.
    /// </summary>
    public bool UserId { get; set; }
}

/// <summary>
/// RFC 9728 protected resource metadata. The root document describes <see cref="OAuthServerOptions.Audience"/>.
/// Each resource this host accepts (<see cref="OAuthServerOptions.Audience"/> and
/// <see cref="OAuthServerOptions.AcceptedAudiences"/>) whose identifier has a path also gets a path-suffixed document,
/// for example <c>https://host/mcp</c> at <c>https://host/.well-known/oauth-protected-resource/mcp</c>.
/// </summary>
public sealed class OAuthProtectedResourceOptions
{
    /// <summary>Map <c>GET /.well-known/oauth-protected-resource</c> and the per-resource documents. Default <see langword="false"/>.</summary>
    public bool Enabled { get; set; }

    /// <summary>Human-readable <c>resource_name</c> of the <see cref="OAuthServerOptions.Audience"/> documents. Optional.</summary>
    public string? ResourceName { get; set; }

    /// <summary>
    /// <c>scopes_supported</c> of the <see cref="OAuthServerOptions.Audience"/> documents. Each must be a configured scope.
    /// Empty (the default) lists every scope.
    /// </summary>
    public IList<string> Scopes { get; } = new List<string>();

    /// <summary>
    /// Path prefixes whose 401 responses get <c>WWW-Authenticate: Bearer resource_metadata="…"</c> pointing at the root
    /// document, from <c>UseOAuthResourceChallenge</c>. Empty means every path that no entry of <see cref="Resources"/> claims.
    /// </summary>
    public IList<string> ChallengePaths { get; } = new List<string>();

    /// <summary>
    /// Settings for the documents of <see cref="OAuthServerOptions.AcceptedAudiences"/> entries other than
    /// <see cref="OAuthServerOptions.Audience"/>: name, scopes, and the paths whose 401 responses point at them.
    /// An accepted resource without an entry still gets a document, with no name and every scope.
    /// </summary>
    public IList<OAuthProtectedResourceDefinition> Resources { get; } = new List<OAuthProtectedResourceDefinition>();
}

/// <summary>The protected resource metadata of one resource in <see cref="OAuthServerOptions.AcceptedAudiences"/>.</summary>
public sealed class OAuthProtectedResourceDefinition
{
    /// <summary>
    /// The resource indicator, exactly as in <see cref="OAuthServerOptions.AcceptedAudiences"/>, for example
    /// <c>https://host/mcp</c>. It needs a path and no query. Required.
    /// </summary>
    public string? Resource { get; set; }

    /// <summary>Human-readable <c>resource_name</c>. Optional.</summary>
    public string? ResourceName { get; set; }

    /// <summary><c>scopes_supported</c>. Each must be a configured scope. Empty (the default) lists every scope.</summary>
    public IList<string> Scopes { get; } = new List<string>();

    /// <summary>
    /// Path prefixes, such as <c>/mcp</c>, whose 401 responses point at this resource's document. Each must start with
    /// <c>/</c> and must not end with one, and no prefix may be listed twice across all resources.
    /// </summary>
    public IList<string> ChallengePaths { get; } = new List<string>();
}

/// <summary>
/// The words a consent page shows for one scope. <see cref="DisplayName"/> and <see cref="Description"/> are the default
/// text; <see cref="DisplayNames"/> and <see cref="Descriptions"/> override them per culture, keyed by culture name such as
/// <c>fr</c> or <c>pt-BR</c>. The request culture is tried first, then its parents (<c>pt-BR</c>, then <c>pt</c>), then the
/// default text.
/// </summary>
public sealed class OAuthScopeDefinition
{
    /// <summary>The scope, as in <see cref="OAuthServerOptions.Scopes"/>. Required.</summary>
    public string? Name { get; set; }

    /// <summary>A short label, such as "Read your reports". Defaults to <see cref="Name"/>.</summary>
    public string? DisplayName { get; set; }

    /// <summary>One or two sentences on what the client can do with this scope. Optional.</summary>
    public string? Description { get; set; }

    /// <summary>Display names per culture name.</summary>
    public IDictionary<string, string> DisplayNames { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Descriptions per culture name.</summary>
    public IDictionary<string, string> Descriptions { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>A client created by <c>SeedOAuthClientsAsync</c>.</summary>
public sealed class OAuthClientDefinition
{
    public string? ClientId { get; set; }

    public string? DisplayName { get; set; }

    /// <summary>Set to make a confidential client. Leave empty for a public client. Prefer a secret store over appsettings.</summary>
    public string? ClientSecret { get; set; }

    public IList<string> RedirectUris { get; } = new List<string>();

    /// <summary>Where the OpenID Connect logout endpoint may send the browser back to. Matched exactly.</summary>
    public IList<string> PostLogoutRedirectUris { get; } = new List<string>();

    /// <summary>Scopes this client may request. Empty means every configured scope.</summary>
    public IList<string> Scopes { get; } = new List<string>();

    /// <summary>Resources this client may request. Empty means every configured resource.</summary>
    public IList<string> Resources { get; } = new List<string>();
}
