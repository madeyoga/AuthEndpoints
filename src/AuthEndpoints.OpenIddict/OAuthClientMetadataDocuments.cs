using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Decides whether this server fetches client ID metadata documents from a host, after
/// <see cref="OAuthClientMetadataDocumentOptions.DeniedHosts"/> and <see cref="OAuthClientMetadataDocumentOptions.AllowedHosts"/>
/// have passed it. Register one with <c>AddClientMetadataHostFilter&lt;T&gt;()</c>, for example to read an allow-list from
/// the database. It is called before every fetch, and before a stored client is reused.
/// </summary>
public interface IOAuthClientMetadataHostFilter
{
    /// <summary>
    /// <see langword="true"/> to accept the client whose <c>client_id</c> is <paramref name="clientId"/>.
    /// A refused client gets <c>invalid_client</c> and no request is made.
    /// </summary>
    ValueTask<bool> IsAllowedAsync(Uri clientId, CancellationToken cancellationToken);
}

internal sealed class AllowAllClientMetadataHosts : IOAuthClientMetadataHostFilter
{
    public ValueTask<bool> IsAllowedAsync(Uri clientId, CancellationToken cancellationToken) => ValueTask.FromResult(true);
}

/// <summary>
/// Runs just before OpenIddict looks the client up. At <c>/connect/authorize</c>, when <c>client_id</c> is an <c>https</c> URL,
/// it makes sure a current copy of that client's metadata document is in the application store, or rejects the request with
/// <c>invalid_client</c>. The error is returned to the browser, never to the client's redirect URI. At <c>/connect/token</c>,
/// it refuses clients created from metadata documents while the feature is turned off, so code exchange and refresh stop too.
/// </summary>
internal sealed class ResolveClientMetadataDocument(OAuthClientMetadataResolver resolver)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessAuthenticationContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessAuthenticationContext context)
    {
        if (context.Request?.ClientId is not { } clientId || !OAuthClientMetadataUrl.LooksLikeOne(clientId))
        {
            return;
        }

        if (context.EndpointType == OpenIddictServerEndpointType.Token)
        {
            if (await resolver.RefusedWhileDisabledAsync(clientId, context.CancellationToken) is { } refused)
            {
                context.Reject(OpenIddictConstants.Errors.InvalidClient, refused);
            }

            return;
        }

        if (context.EndpointType != OpenIddictServerEndpointType.Authorization)
        {
            return;
        }

        var caller = context.Transaction.GetHttpRequest()?.HttpContext.Connection.RemoteIpAddress;
        if (await resolver.ResolveAsync(clientId, caller, context.CancellationToken) is { } error)
        {
            context.Reject(OpenIddictConstants.Errors.InvalidClient, error);
        }
    }
}

/// <summary>Fetches, checks, and stores client ID metadata documents.</summary>
internal sealed class OAuthClientMetadataResolver(
    IOpenIddictApplicationManager applications,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens,
    OAuthClientMetadataFetcher fetcher,
    OAuthClientMetadataRateLimiter limiter,
    IOAuthClientMetadataHostFilter hostFilter,
    IOptions<OAuthServerOptions> options,
    TimeProvider clock)
{
    /// <summary>
    /// The <c>error_description</c> for a token request from a client created from a metadata document while
    /// <see cref="OAuthClientMetadataDocumentOptions.Enabled"/> is off, or <see langword="null"/> to let it through.
    /// </summary>
    public async Task<string?> RefusedWhileDisabledAsync(string clientId, CancellationToken cancellationToken)
    {
        if (options.Value.ClientMetadataDocuments.Enabled
            || await applications.FindByClientIdAsync(clientId, cancellationToken) is not { } application)
        {
            return null;
        }

        return OAuthClientMetadataUrl.IsMetadataClient(await applications.GetSettingsAsync(application, cancellationToken))
            ? DisabledError
            : null;
    }

    private const string DisabledError = "Client ID metadata documents are not accepted.";

    /// <summary>
    /// Returns <see langword="null"/> when the request may go on (the client is stored and current, or it is a configured
    /// client that happens to use a URL as its id), or the <c>error_description</c> to reject it with.
    /// </summary>
    public async Task<string?> ResolveAsync(string clientId, IPAddress? caller, CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var documents = settings.ClientMetadataDocuments;
        var application = await applications.FindByClientIdAsync(clientId, cancellationToken);
        var stored = application is null ? null : await applications.GetSettingsAsync(application, cancellationToken);
        if (application is not null && !OAuthClientMetadataUrl.IsMetadataClient(stored!))
        {
            // A configured client, a developer app, or a registered client: never replaced by a fetched document.
            return null;
        }

        if (!documents.Enabled)
        {
            // Unknown clients are refused by OpenIddict. Stored ones stop working at authorize when the feature is turned off.
            return application is null ? null : DisabledError;
        }

        if (!OAuthClientMetadataUrl.TryParse(clientId, out var url, out var invalid))
        {
            return invalid;
        }

        if (!OAuthClientMetadataHosts.Allows(documents, url.IdnHost) || !await hostFilter.IsAllowedAsync(url, cancellationToken))
        {
            return "This server does not accept clients from this host.";
        }

        var now = clock.GetUtcNow();
        if (application is not null && OAuthClientMetadataUrl.ExpiresAt(stored!) is { } expires && expires > now)
        {
            return null;
        }

        using (var lease = limiter.Acquire(caller))
        {
            if (!lease.IsAcquired)
            {
                // A stored copy is still better than nothing; it is fetched again on a later request.
                return application is null ? "Too many client metadata requests. Try again later." : null;
            }
        }

        var fetched = await fetcher.FetchAsync(url, cancellationToken);
        OpenIddictApplicationDescriptor descriptor;
        if (fetched.Error is { } error)
        {
            // The draft: a network failure or timeout should not discard metadata that was valid.
            return fetched.Transient && application is not null ? null : error;
        }

        using (var document = fetched.Document!)
        {
            if (application is not null && !OAuthClientMetadataDocument.ClientIdMatches(document.RootElement, clientId))
            {
                // The draft: a client_id mismatch should invalidate what the client already holds. Revoke every grant
                // and token of the stored client. Other invalid documents only refuse new authorizations.
                var applicationId = await applications.GetIdAsync(application, cancellationToken);
                if (!string.IsNullOrEmpty(applicationId))
                {
                    await tokens.RevokeByApplicationIdAsync(applicationId, cancellationToken);
                    await authorizations.RevokeByApplicationIdAsync(applicationId, cancellationToken);
                }

                return OAuthClientMetadataDocument.MismatchError;
            }

            if (!OAuthClientMetadataDocument.TryCreateDescriptor(clientId, url, document.RootElement, settings, out var parsed, out var rejected))
            {
                return rejected;
            }

            descriptor = parsed;
        }

        var lifetime = OAuthClientMetadataCache.Lifetime(fetched.MaxAge, documents);
        descriptor.Settings[OAuthServerConstants.CreatedAtSetting] = stored is not null
            && stored.TryGetValue(OAuthServerConstants.CreatedAtSetting, out var created)
                ? created
                : now.ToString("O", CultureInfo.InvariantCulture);
        descriptor.Settings[OAuthServerConstants.ClientMetadataExpiresSetting] = (now + lifetime).ToString("O", CultureInfo.InvariantCulture);

        if (application is not null)
        {
            await applications.UpdateAsync(application, descriptor, cancellationToken);
            return null;
        }

        try
        {
            await applications.CreateAsync(descriptor, cancellationToken);
        }
        catch (OpenIddictExceptions.ValidationException)
        {
            // Another request stored the same client first. OpenIddict checks for a duplicate client id before it adds
            // the row, so nothing is left tracked in the DbContext.
            if (await applications.FindByClientIdAsync(clientId, cancellationToken) is null)
            {
                throw;
            }
        }

        return null;
    }
}

internal static class OAuthClientMetadataUrl
{
    private const int MaxLength = OAuthRequestLimits.ClientIdLength;

    /// <summary>Cheap test before any lookup: only <c>https</c> URLs are metadata document client ids.</summary>
    public static bool LooksLikeOne(string clientId) => clientId.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    /// <summary>Whether a stored application came from a metadata document.</summary>
    public static bool IsMetadataClient(IReadOnlyDictionary<string, string> settings)
        => settings.ContainsKey(OAuthServerConstants.ClientMetadataExpiresSetting);

    public static DateTimeOffset? ExpiresAt(IReadOnlyDictionary<string, string> settings)
        => settings.TryGetValue(OAuthServerConstants.ClientMetadataExpiresSetting, out var raw)
            && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var value)
                ? value
                : null;

    /// <summary>
    /// The draft's client identifier URL rules: <c>https</c>, a path other than <c>/</c>, no dot segments, no user info,
    /// no fragment. A query is refused too (the draft says it should not be used). The URL is never normalized.
    /// </summary>
    public static bool TryParse(string value, out Uri url, out string error)
    {
        url = null!;
        error = "client_id must be an https URL with a path, and no query, fragment, user info, or dot segments.";
        if (value.Length > MaxLength
            || value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character))
            || value.Contains('\\')
            || !Uri.TryCreate(value, UriKind.Absolute, out var parsed)
            || parsed.Scheme != Uri.UriSchemeHttps
            || value.Contains('?') || value.Contains('#')
            || !string.IsNullOrEmpty(parsed.UserInfo) || value.Contains('@'))
        {
            return false;
        }

        // Read the path from the original text: Uri removes dot segments while parsing.
        var authorityEnd = value.IndexOf('/', "https://".Length);
        var path = authorityEnd < 0 ? string.Empty : value[authorityEnd..];
        if (path.Length <= 1 || path.Split('/').Any(segment => segment is "." or ".." || segment.Equals("%2e", StringComparison.OrdinalIgnoreCase)
                || segment.Equals("%2e%2e", StringComparison.OrdinalIgnoreCase) || segment.Equals(".%2e", StringComparison.OrdinalIgnoreCase)
                || segment.Equals("%2e.", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        url = parsed;
        return true;
    }

    /// <summary>Host plus the port when it is not the default, as the consent card shows it.</summary>
    public static string? Host(string clientId)
        => Uri.TryCreate(clientId, UriKind.Absolute, out var url) ? url.Authority : null;
}

internal static class OAuthClientMetadataHosts
{
    public static bool Allows(OAuthClientMetadataDocumentOptions options, string host)
    {
        host = host.TrimEnd('.');
        if (options.DeniedHosts.Any(pattern => Matches(pattern, host)))
        {
            return false;
        }

        return options.AllowedHosts.Count == 0 || options.AllowedHosts.Any(pattern => Matches(pattern, host));
    }

    /// <summary><c>example.com</c> matches only itself; <c>*.example.com</c> matches its subdomains, not itself.</summary>
    public static bool Matches(string pattern, string host)
        => pattern.StartsWith("*.", StringComparison.Ordinal)
            ? host.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase) && host.Length > pattern.Length - 1
            : string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);

    /// <summary>A host name or <c>*.</c> plus a host name. No scheme, port, path, or IP address.</summary>
    public static bool IsValidPattern(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        var host = pattern.StartsWith("*.", StringComparison.Ordinal) ? pattern[2..] : pattern;
        return Uri.CheckHostName(host) == UriHostNameType.Dns && !host.Contains('*');
    }
}

internal static class OAuthClientMetadataCache
{
    public static TimeSpan Lifetime(TimeSpan? maxAge, OAuthClientMetadataDocumentOptions options)
    {
        var requested = maxAge ?? TimeSpan.Zero;
        if (requested < options.MinCacheDuration)
        {
            return options.MinCacheDuration;
        }

        return requested > options.MaxCacheDuration ? options.MaxCacheDuration : requested;
    }

    /// <summary><c>max-age</c> from <c>Cache-Control</c>; <c>no-store</c> and <c>no-cache</c> count as zero.</summary>
    public static TimeSpan? MaxAge(CacheControlHeaderValue? cacheControl)
        => cacheControl is null ? null
            : cacheControl.NoStore || cacheControl.NoCache ? TimeSpan.Zero
            : cacheControl.MaxAge;
}

/// <summary>Turns a fetched document into an OpenIddict application, or explains why it is refused.</summary>
internal static class OAuthClientMetadataDocument
{
    private static readonly string[] SharedSecretMethods =
    [
        OpenIddictConstants.ClientAuthenticationMethods.ClientSecretBasic,
        OpenIddictConstants.ClientAuthenticationMethods.ClientSecretPost,
        OpenIddictConstants.ClientAuthenticationMethods.ClientSecretJwt,
    ];

    public const string MismatchError = "The client metadata document's client_id does not match its URL.";

    /// <summary>Whether the document's <c>client_id</c> is exactly <paramref name="clientId"/>, compared as a string.</summary>
    public static bool ClientIdMatches(JsonElement document, string clientId)
        => document.ValueKind == JsonValueKind.Object
            && TryString(document, "client_id", out var value)
            && string.Equals(value, clientId, StringComparison.Ordinal);

    public static bool TryCreateDescriptor(
        string clientId,
        Uri url,
        JsonElement document,
        OAuthServerOptions settings,
        out OpenIddictApplicationDescriptor descriptor,
        out string error)
    {
        descriptor = null!;
        error = string.Empty;
        if (document.ValueKind != JsonValueKind.Object)
        {
            error = "The client metadata document is not a JSON object.";
            return false;
        }

        // Simple string comparison, as the draft requires: no normalization.
        if (!ClientIdMatches(document, clientId))
        {
            error = MismatchError;
            return false;
        }

        if (document.TryGetProperty("client_secret", out _) || document.TryGetProperty("client_secret_expires_at", out _))
        {
            error = "A client metadata document must not contain a client secret.";
            return false;
        }

        if (document.TryGetProperty("jwks", out _) && document.TryGetProperty("jwks_uri", out _))
        {
            error = "A client metadata document must not contain both jwks and jwks_uri.";
            return false;
        }

        if (!TryAuthenticationMethods(document, out var methods, out error))
        {
            return false;
        }

        if (methods.Any(method => SharedSecretMethods.Contains(method, StringComparer.Ordinal)))
        {
            error = "A client metadata document must not use a shared-secret authentication method.";
            return false;
        }

        if (!methods.Contains(OpenIddictConstants.ClientAuthenticationMethods.None, StringComparer.Ordinal))
        {
            error = methods.Contains(OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt, StringComparer.Ordinal)
                ? "private_key_jwt is not supported for client ID metadata documents yet. Offer token_endpoint_auth_method none."
                : "This server accepts only public clients from metadata documents (token_endpoint_auth_method none).";
            return false;
        }

        var registration = settings.DynamicRegistration;
        if (!TryStrings(document, "redirect_uris", out var redirects) || redirects is not { Length: > 0 })
        {
            error = "The client metadata document must list redirect_uris.";
            return false;
        }

        if (redirects.Length > registration.MaxRedirectUris)
        {
            error = $"redirect_uris is limited to {registration.MaxRedirectUris} entries.";
            return false;
        }

        if (redirects.Any(redirect => !OAuthRedirects.IsAllowedPublicClientRedirect(redirect)))
        {
            error = "A redirect URI must be https, or http on localhost, 127.0.0.1, or [::1], with no fragment.";
            return false;
        }

        // The draft: intersect with what this server supports, and refuse an empty intersection.
        var refresh = true;
        if (document.TryGetProperty("grant_types", out _))
        {
            if (!TryStrings(document, "grant_types", out var grants)
                || !grants!.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode, StringComparer.Ordinal))
            {
                error = "grant_types must include authorization_code.";
                return false;
            }

            refresh = grants.Contains(OpenIddictConstants.GrantTypes.RefreshToken, StringComparer.Ordinal);
        }

        if (document.TryGetProperty("response_types", out _)
            && (!TryStrings(document, "response_types", out var responses)
                || !responses!.Contains(OpenIddictConstants.ResponseTypes.Code, StringComparer.Ordinal)))
        {
            error = "response_types must include code.";
            return false;
        }

        string clientName;
        if (document.TryGetProperty("client_name", out _))
        {
            if (!TryString(document, "client_name", out var name))
            {
                error = "client_name must be a string.";
                return false;
            }

            clientName = string.IsNullOrWhiteSpace(name) ? url.Authority : name.Trim();
        }
        else
        {
            clientName = url.Authority;
        }

        if (clientName.Length > registration.MaxClientNameLength)
        {
            error = $"client_name is limited to {registration.MaxClientNameLength} characters.";
            return false;
        }

        var scopes = settings.DynamicRegistrationScopes();
        var openId = scopes.Contains(OAuthServerConstants.OpenIdScope, StringComparer.Ordinal);
        string[] postLogout = [];
        if (openId && document.TryGetProperty("post_logout_redirect_uris", out _))
        {
            if (!TryStrings(document, "post_logout_redirect_uris", out var listed)
                || listed!.Length > registration.MaxRedirectUris
                || listed.Any(redirect => !OAuthRedirects.IsAllowedPublicClientRedirect(redirect)))
            {
                error = "post_logout_redirect_uris must list https URIs, or http on localhost, 127.0.0.1, or [::1], with no fragment.";
                return false;
            }

            postLogout = listed;
        }

        descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            DisplayName = clientName,
        };
        foreach (var redirect in redirects.Distinct(StringComparer.Ordinal))
        {
            descriptor.RedirectUris.Add(new Uri(redirect));
        }

        foreach (var redirect in postLogout.Distinct(StringComparer.Ordinal))
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(redirect));
        }

        // The document's scope is ignored: it is published for every server, so it cannot name this server's scopes.
        OAuthClientPermissions.AddCodeFlow(descriptor, scopes, settings.AllResources());
        if (!refresh)
        {
            descriptor.Permissions.Remove(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        }

        return true;
    }

    /// <summary>
    /// The methods the client may use: <c>token_endpoint_auth_method</c>, else <c>token_endpoint_auth_methods_supported</c>,
    /// else <c>none</c> (the draft replaces RFC 7591's <c>client_secret_basic</c> default).
    /// </summary>
    private static bool TryAuthenticationMethods(JsonElement document, out string[] methods, out string error)
    {
        methods = [];
        error = string.Empty;
        string[]? supported = null;
        if (document.TryGetProperty("token_endpoint_auth_methods_supported", out _)
            && !TryStrings(document, "token_endpoint_auth_methods_supported", out supported))
        {
            error = "token_endpoint_auth_methods_supported must be an array of strings.";
            return false;
        }

        if (document.TryGetProperty("token_endpoint_auth_method", out _))
        {
            if (!TryString(document, "token_endpoint_auth_method", out var method))
            {
                error = "token_endpoint_auth_method must be a string.";
                return false;
            }

            if (supported is not null && !supported.Contains(method, StringComparer.Ordinal))
            {
                error = "token_endpoint_auth_method must be one of token_endpoint_auth_methods_supported.";
                return false;
            }

            methods = supported is null ? [method] : [method, .. supported];
            return true;
        }

        methods = supported ?? [OpenIddictConstants.ClientAuthenticationMethods.None];
        return true;
    }

    private static bool TryString(JsonElement document, string name, out string value)
    {
        value = string.Empty;
        if (!document.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString()!;
        return true;
    }

    private static bool TryStrings(JsonElement document, string name, out string[]? values)
    {
        values = null;
        if (!document.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var list = new List<string>();
        foreach (var item in property.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            list.Add(item.GetString()!);
        }

        values = list.ToArray();
        return true;
    }
}

/// <summary>Resolves a host name to its addresses. Replaced in tests.</summary>
internal interface IOAuthClientMetadataDnsResolver
{
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

internal sealed class SystemClientMetadataDnsResolver : IOAuthClientMetadataDnsResolver
{
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        => Dns.GetHostAddressesAsync(host, cancellationToken);
}

internal sealed record OAuthClientMetadataFetch(JsonDocument? Document, TimeSpan? MaxAge, string? Error, bool Transient)
{
    public static OAuthClientMetadataFetch Failed(string error, bool transient) => new(null, null, error, transient);
}

/// <summary>
/// Fetches one document. The host is resolved first and every address must be public; the connection then goes only to
/// those addresses, so a second DNS answer cannot point it somewhere else. No redirects, no cookies, no proxy, a timeout,
/// and a size limit. Nothing is logged.
/// </summary>
internal sealed class OAuthClientMetadataFetcher(
    IHttpClientFactory httpClients,
    IOAuthClientMetadataDnsResolver dns,
    IOptions<OAuthServerOptions> options)
{
    public const string HttpClientName = "AuthEndpoints.OpenIddict.ClientMetadata";

    internal static readonly HttpRequestOptionsKey<IPAddress[]> AddressesKey = new("AuthEndpoints.OpenIddict.ClientMetadata.Addresses");

    public async Task<OAuthClientMetadataFetch> FetchAsync(Uri url, CancellationToken cancellationToken)
    {
        var settings = options.Value.ClientMetadataDocuments;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(settings.FetchTimeout);
        try
        {
            IPAddress[] addresses;
            if (url.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6
                && IPAddress.TryParse(url.DnsSafeHost, out var literal))
            {
                addresses = [literal];
            }
            else
            {
                try
                {
                    addresses = await dns.ResolveAsync(url.IdnHost, timeout.Token);
                }
                catch (SocketException)
                {
                    return OAuthClientMetadataFetch.Failed("The client metadata document's host could not be resolved.", transient: true);
                }
            }

            if (addresses.Length == 0)
            {
                return OAuthClientMetadataFetch.Failed("The client metadata document's host could not be resolved.", transient: true);
            }

            if (!addresses.All(OAuthClientMetadataAddresses.IsPublic))
            {
                return OAuthClientMetadataFetch.Failed("The client metadata document's host is not a public address.", transient: false);
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Options.Set(AddressesKey, addresses);
            using var client = httpClients.CreateClient(HttpClientName);
            client.Timeout = Timeout.InfiniteTimeSpan;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            var status = (int)response.StatusCode;
            if (status is >= 300 and < 400)
            {
                return OAuthClientMetadataFetch.Failed("The client metadata document URL redirected. Redirects are not followed.", transient: false);
            }

            if (status is >= 500 or 429 or 408)
            {
                return OAuthClientMetadataFetch.Failed("The client metadata document could not be retrieved.", transient: true);
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return OAuthClientMetadataFetch.Failed("The client metadata document could not be retrieved.", transient: false);
            }

            if (response.Content.Headers.ContentLength > settings.MaxDocumentBytes)
            {
                return OAuthClientMetadataFetch.Failed("The client metadata document is too large.", transient: false);
            }

            var body = await ReadLimitedAsync(response.Content, settings.MaxDocumentBytes, timeout.Token);
            if (body is null)
            {
                return OAuthClientMetadataFetch.Failed("The client metadata document is too large.", transient: false);
            }

            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 16 });
            }
            catch (JsonException)
            {
                return OAuthClientMetadataFetch.Failed("The client metadata document is not valid JSON.", transient: false);
            }

            return new OAuthClientMetadataFetch(document, OAuthClientMetadataCache.MaxAge(response.Headers.CacheControl), null, false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return OAuthClientMetadataFetch.Failed("The client metadata document could not be retrieved in time.", transient: true);
        }
        catch (HttpRequestException)
        {
            return OAuthClientMetadataFetch.Failed("The client metadata document could not be retrieved.", transient: true);
        }
    }

    /// <summary>The body, or <see langword="null"/> when it is longer than <paramref name="limit"/> bytes.</summary>
    private static async Task<byte[]?> ReadLimitedAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[limit + 1];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total > limit ? null : buffer[..total];
    }

    /// <summary>
    /// The production handler. It connects only to the addresses <see cref="FetchAsync"/> checked, read from the request,
    /// and checks them again, so DNS rebinding cannot reach a private address.
    /// </summary>
    internal static SocketsHttpHandler CreateHandler(OAuthClientMetadataDocumentOptions settings) => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        AutomaticDecompression = DecompressionMethods.None,
        ConnectTimeout = settings.FetchTimeout,
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectCallback = async (context, cancellationToken) =>
        {
            if (!context.InitialRequestMessage.Options.TryGetValue(AddressesKey, out var addresses)
                || addresses is not { Length: > 0 }
                || !addresses.All(OAuthClientMetadataAddresses.IsPublic))
            {
                throw new HttpRequestException("The client metadata document's address was not checked.");
            }

            Exception? last = null;
            foreach (var address in addresses)
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException)
                {
                    socket.Dispose();
                    last = ex;
                    if (ex is OperationCanceledException)
                    {
                        throw;
                    }
                }
            }

            throw new HttpRequestException("The client metadata document's host could not be reached.", last);
        },
    };
}

/// <summary>Refuses loopback, private, link-local, and other special-use addresses (RFC 6890).</summary>
internal static class OAuthClientMetadataAddresses
{
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return IsPublic(address.MapToIPv4());
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return IsPublicV4(bytes);
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6 || bytes.Length != 16)
        {
            return false;
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.IPv6None) || address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal || address.IsIPv6Multicast || address.IsIPv6UniqueLocal || address.IsIPv6Teredo)
        {
            return false;
        }

        // Only global unicast (2000::/3) is public.
        if ((bytes[0] & 0xE0) != 0x20)
        {
            return false;
        }

        // 2001::/23 (IETF protocol assignments, Teredo, ORCHID), 2001:db8::/32 (documentation), 3fff::/20 (documentation).
        if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] < 0x02)
        {
            return false;
        }

        if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
        {
            return false;
        }

        if (bytes[0] == 0x3f && bytes[1] == 0xff && bytes[2] < 0x10)
        {
            return false;
        }

        // 2002::/16 (6to4) carries an IPv4 address: check it.
        if (bytes[0] == 0x20 && bytes[1] == 0x02)
        {
            return IsPublicV4(bytes[2..6]);
        }

        return true;
    }

    private static bool IsPublicV4(byte[] b)
        => !(b[0] == 0 // 0.0.0.0/8
            || b[0] == 10 // 10.0.0.0/8
            || b[0] == 100 && b[1] >= 64 && b[1] <= 127 // 100.64.0.0/10 shared address space
            || b[0] == 127 // loopback
            || b[0] == 169 && b[1] == 254 // link-local, cloud metadata
            || b[0] == 172 && b[1] >= 16 && b[1] <= 31 // 172.16.0.0/12
            || b[0] == 192 && b[1] == 0 && b[2] == 0 // 192.0.0.0/24 protocol assignments
            || b[0] == 192 && b[1] == 0 && b[2] == 2 // TEST-NET-1
            || b[0] == 192 && b[1] == 88 && b[2] == 99 // 6to4 relay anycast
            || b[0] == 192 && b[1] == 168 // 192.168.0.0/16
            || b[0] == 198 && (b[1] == 18 || b[1] == 19) // benchmarking
            || b[0] == 198 && b[1] == 51 && b[2] == 100 // TEST-NET-2
            || b[0] == 203 && b[1] == 0 && b[2] == 113 // TEST-NET-3
            || b[0] >= 224); // multicast, reserved, broadcast
}

/// <summary>Fixed window per caller IP address for document fetches that authorize requests cause.</summary>
internal sealed class OAuthClientMetadataRateLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<string> limiter;

    public OAuthClientMetadataRateLimiter(IOptions<OAuthServerOptions> options)
    {
        var permits = Math.Max(1, options.Value.ClientMetadataDocuments.FetchesPerMinute);
        limiter = PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetFixedWindowLimiter(
            key,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
    }

    public RateLimitLease Acquire(IPAddress? caller) => limiter.AttemptAcquire(caller?.ToString() ?? "unknown");

    public void Dispose() => limiter.Dispose();
}
