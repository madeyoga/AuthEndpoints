using System.Globalization;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// <c>POST /connect/register</c> (RFC 7591). Public clients only, with an https or loopback redirect URI.
/// The limiter lives in the endpoint, so it works without <c>UseRateLimiter</c>.
/// </summary>
internal static class OAuthRegistrationEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext http,
        RegisterClientBody? body,
        OAuthRegistrationRateLimiter limiter,
        IOpenIddictApplicationManager applications,
        IOptions<OAuthServerOptions> options,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        using var lease = limiter.Acquire(http);
        if (!lease.IsAcquired)
        {
            return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "Too Many Requests");
        }

        var settings = options.Value;
        var registration = settings.DynamicRegistration;
        if (body?.RedirectUris is not { Length: > 0 } redirects)
        {
            return Error("invalid_redirect_uri", "redirect_uris must list at least one absolute URI.");
        }

        if (redirects.Length > registration.MaxRedirectUris)
        {
            return Error("invalid_redirect_uri", $"redirect_uris is limited to {registration.MaxRedirectUris} entries.");
        }

        foreach (var redirect in redirects)
        {
            if (!OAuthRedirects.IsAllowedPublicClientRedirect(redirect))
            {
                return Error(
                    "invalid_redirect_uri",
                    "A redirect URI must be https, or http on localhost, 127.0.0.1, or [::1], with no fragment.");
            }
        }

        var scopes = settings.DynamicRegistrationScopes();
        var openId = scopes.Contains(OAuthServerConstants.OpenIdScope, StringComparer.Ordinal);

        // OpenID Connect RP-Initiated Logout metadata. Ignored, as unknown metadata is, when the client may not use openid.
        var postLogout = openId ? body.PostLogoutRedirectUris ?? [] : [];
        if (postLogout.Length > registration.MaxRedirectUris)
        {
            return Error("invalid_client_metadata", $"post_logout_redirect_uris is limited to {registration.MaxRedirectUris} entries.");
        }

        if (postLogout.Any(redirect => !OAuthRedirects.IsAllowedPublicClientRedirect(redirect)))
        {
            return Error(
                "invalid_client_metadata",
                "A post-logout redirect URI must be https, or http on localhost, 127.0.0.1, or [::1], with no fragment.");
        }

        if (!string.IsNullOrEmpty(body.ClientSecret)
            || body.TokenEndpointAuthMethod is { Length: > 0 } method
                && !string.Equals(method, OpenIddictConstants.ClientAuthenticationMethods.None, StringComparison.Ordinal))
        {
            return Error("invalid_client_metadata", "Only public clients are supported. token_endpoint_auth_method must be none.");
        }

        if (body.GrantTypes is { } grants
            && grants.Any(grant => grant is not (OpenIddictConstants.GrantTypes.AuthorizationCode or OpenIddictConstants.GrantTypes.RefreshToken)))
        {
            return Error("invalid_client_metadata", "grant_types must be authorization_code, refresh_token, or omitted.");
        }

        if (body.ResponseTypes is { } responses && responses.Any(response => response != OpenIddictConstants.ResponseTypes.Code))
        {
            return Error("invalid_client_metadata", "response_types must be code, or omitted.");
        }

        var known = settings.AllScopes().ToHashSet(StringComparer.Ordinal);
        foreach (var item in OAuthScopes.Split(body.Scope))
        {
            if (!known.Contains(item))
            {
                return Error("invalid_client_metadata", $"The scope '{item}' is not supported.");
            }

            if (!settings.AllowsDynamicRegistrationScope(item))
            {
                return Error("invalid_client_metadata", $"The scope '{item}' is not available to dynamically registered clients.");
            }
        }

        var clientName = string.IsNullOrWhiteSpace(body.ClientName)
            ? OAuthServerConstants.FallbackClientName
            : body.ClientName.Trim();
        if (clientName.Length > registration.MaxClientNameLength)
        {
            return Error("invalid_client_metadata", $"client_name is limited to {registration.MaxClientNameLength} characters.");
        }

        var now = clock.GetUtcNow();
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = Guid.CreateVersion7().ToString("N"),
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

        OAuthClientPermissions.AddCodeFlow(descriptor, scopes, settings.AllResources());
        descriptor.Settings[OAuthServerConstants.CreatedAtSetting] = now.ToString("O", CultureInfo.InvariantCulture);
        await applications.CreateAsync(descriptor, cancellationToken);

        return Results.Json(
            new RegisterClientResponse(
                descriptor.ClientId,
                now.ToUnixTimeSeconds(),
                OpenIddictConstants.ClientAuthenticationMethods.None,
                descriptor.RedirectUris.Select(uri => uri.OriginalString).ToArray(),
                [OpenIddictConstants.GrantTypes.AuthorizationCode, OpenIddictConstants.GrantTypes.RefreshToken],
                [OpenIddictConstants.ResponseTypes.Code],
                clientName)
            {
                PostLogoutRedirectUris = descriptor.PostLogoutRedirectUris.Count == 0
                    ? null
                    : descriptor.PostLogoutRedirectUris.Select(uri => uri.OriginalString).ToArray(),
            },
            statusCode: StatusCodes.Status201Created);
    }

    private static IResult Error(string error, string description)
        => Results.Json(new OAuthProtocolError(error, description), statusCode: StatusCodes.Status400BadRequest);
}

/// <summary>Fixed window per client IP address for anonymous registration.</summary>
internal sealed class OAuthRegistrationRateLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<HttpContext> limiter;

    public OAuthRegistrationRateLimiter(IOptions<OAuthServerOptions> options)
    {
        var permits = Math.Max(1, options.Value.DynamicRegistration.PermitsPerMinute);
        limiter = PartitionedRateLimiter.Create<HttpContext, string>(http => RateLimitPartition.GetFixedWindowLimiter(
            http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
    }

    public RateLimitLease Acquire(HttpContext http) => limiter.AttemptAcquire(http);

    public void Dispose() => limiter.Dispose();
}

internal static class OAuthClientPermissions
{
    /// <summary>The OpenID Connect permissions, when openid is configured. For clients created before it was.</summary>
    public static void AddOpenIdConnect(OpenIddictApplicationDescriptor descriptor, OAuthServerOptions settings)
    {
        if (settings.OpenIdConnectEnabled)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + OAuthServerConstants.OpenIdScope);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);
        }
    }

    public static void AddCodeFlow(
        OpenIddictApplicationDescriptor descriptor, IEnumerable<string> scopes, IEnumerable<string> resources)
    {
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        foreach (var scope in scopes.Where(scope => scope != OAuthServerConstants.OfflineAccessScope))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        // A client allowed to sign users in with OpenID Connect may also send them to logout.
        if (scopes.Contains(OAuthServerConstants.OpenIdScope, StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);
        }

        foreach (var resource in resources)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Resource + resource);
        }

        descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
    }
}

internal sealed record OAuthProtocolError(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);

internal sealed class RegisterClientBody
{
    [JsonPropertyName("redirect_uris")]
    public string[]? RedirectUris { get; init; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("grant_types")]
    public string[]? GrantTypes { get; init; }

    [JsonPropertyName("response_types")]
    public string[]? ResponseTypes { get; init; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; init; }

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("post_logout_redirect_uris")]
    public string[]? PostLogoutRedirectUris { get; init; }
}

internal sealed record RegisterClientResponse(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("client_id_issued_at")] long ClientIdIssuedAt,
    [property: JsonPropertyName("token_endpoint_auth_method")] string TokenEndpointAuthMethod,
    [property: JsonPropertyName("redirect_uris")] string[] RedirectUris,
    [property: JsonPropertyName("grant_types")] string[] GrantTypes,
    [property: JsonPropertyName("response_types")] string[] ResponseTypes,
    [property: JsonPropertyName("client_name")] string ClientName)
{
    [JsonPropertyName("post_logout_redirect_uris")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? PostLogoutRedirectUris { get; init; }
}
