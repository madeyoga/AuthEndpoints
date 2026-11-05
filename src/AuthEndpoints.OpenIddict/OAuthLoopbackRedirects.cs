using System.Net;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Replaces OpenIddict's <c>ValidateClientRedirectUri</c>. A redirect URI on a loopback IP literal (<c>http://127.0.0.1</c>
/// or <c>http://[::1]</c>) may use any port, as RFC 8252 §7.3 requires, when a registered URI matches it in everything else.
/// Every other redirect URI, including an exact match, goes to the built-in check unchanged.
/// </summary>
internal sealed class ValidateClientRedirectUriWithLoopbackPorts(IOpenIddictApplicationManager applications)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>
{
    private readonly OpenIddictServerHandlers.Authentication.ValidateClientRedirectUri builtIn = new(applications);

    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidateAuthorizationRequestContext context)
    {
        if (OAuthLoopbackRedirects.TryParse(context.RedirectUri, out var requested)
            && !string.IsNullOrEmpty(context.ClientId)
            && await applications.FindByClientIdAsync(context.ClientId, context.CancellationToken) is { } application)
        {
            foreach (var registered in await applications.GetRedirectUrisAsync(application, context.CancellationToken))
            {
                if (OAuthLoopbackRedirects.MatchesIgnoringPort(registered, requested))
                {
                    return;
                }
            }
        }

        await builtIn.HandleAsync(context);
    }
}

internal static class OAuthLoopbackRedirects
{
    /// <summary>
    /// Whether <paramref name="redirectUri"/> is still registered for the application: an exact match, or a loopback IP
    /// URI that matches a registered one in everything but the port. The same rule authorize applies.
    /// </summary>
    public static async ValueTask<bool> IsRegisteredAsync(
        IOpenIddictApplicationManager applications, object application, string redirectUri, CancellationToken cancellationToken)
    {
        if (await applications.ValidateRedirectUriAsync(application, redirectUri, cancellationToken))
        {
            return true;
        }

        if (!TryParse(redirectUri, out var requested))
        {
            return false;
        }

        foreach (var registered in await applications.GetRedirectUrisAsync(application, cancellationToken))
        {
            if (MatchesIgnoringPort(registered, requested))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>An <c>http</c> URI on a loopback IP literal, with no user info or fragment. <c>localhost</c> is not one.</summary>
    public static bool TryParse(string? value, out Uri uri)
    {
        uri = null!;
        return value is not null
            && Uri.TryCreate(value, UriKind.Absolute, out uri!)
            && IsLoopbackIp(uri);
    }

    /// <summary>Same scheme, host, path, and query. Only the port may differ.</summary>
    public static bool MatchesIgnoringPort(string? registered, Uri requested)
        => TryParse(registered, out var candidate)
            && string.Equals(candidate.Host, requested.Host, StringComparison.OrdinalIgnoreCase)
            && string.Equals(candidate.PathAndQuery, requested.PathAndQuery, StringComparison.Ordinal);

    private static bool IsLoopbackIp(Uri uri)
        => uri.Scheme == Uri.UriSchemeHttp
            && uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6
            && IPAddress.TryParse(uri.DnsSafeHost, out var address)
            && IPAddress.IsLoopback(address)
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Fragment);
}
