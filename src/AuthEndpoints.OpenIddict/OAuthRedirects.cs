using Microsoft.AspNetCore.WebUtilities;

namespace AuthEndpoints.OpenIddict;

internal static class OAuthRedirects
{
    /// <summary>An authorization response redirect with the RFC 9207 <c>iss</c> parameter.</summary>
    public static string Authorization(
        string redirectUri, string? code, string? state, string issuer, string? error, string? description)
    {
        var query = new Dictionary<string, string?>();
        if (code is not null)
        {
            query["code"] = code;
        }

        if (error is not null)
        {
            query["error"] = error;
        }

        if (description is not null)
        {
            query["error_description"] = description;
        }

        if (!string.IsNullOrEmpty(state))
        {
            query["state"] = state;
        }

        query["iss"] = issuer;
        return QueryHelpers.AddQueryString(redirectUri, query);
    }

    /// <summary>Host plus the port when it is not the default.</summary>
    public static string Host(string redirectUri) => new Uri(redirectUri).Authority;

    /// <summary>https, or http on a loopback host, with no fragment or user info.</summary>
    public static bool IsAllowedPublicClientRedirect(string? value)
        => TryParse(value, out var uri) && IsWebOrLoopback(uri);

    /// <summary>
    /// A developer app redirect: https, or http on a loopback host, for any app. A public app may also use a
    /// private-use scheme (RFC 8252 §7.1) such as <c>com.example.app:/callback</c>. No fragment or user info.
    /// </summary>
    public static bool IsAllowedDeveloperAppRedirect(string? value, bool confidential)
    {
        if (!TryParse(value, out var uri))
        {
            return false;
        }

        if (IsWebOrLoopback(uri))
        {
            return true;
        }

        return !confidential && IsPrivateUseScheme(uri.Scheme);
    }

    /// <summary>An absolute http or https URL with no user info.</summary>
    public static bool IsHomepage(string? value)
        => TryParse(value, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);

    private static bool TryParse(string? value, out Uri uri)
    {
        uri = null!;
        return value is not null && value.Length <= 2048
            && Uri.TryCreate(value, UriKind.Absolute, out uri!)
            && string.IsNullOrEmpty(uri.Fragment)
            && string.IsNullOrEmpty(uri.UserInfo);
    }

    // IsLoopback covers localhost, 127.0.0.0/8, and [::1].
    private static bool IsWebOrLoopback(Uri uri)
        => uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;

    /// <summary>
    /// A reverse-domain scheme with at least one dot, so <c>javascript:</c>, <c>data:</c>, <c>file:</c>, and
    /// other single-word schemes are never accepted.
    /// </summary>
    private static bool IsPrivateUseScheme(string scheme)
        => scheme.Contains('.', StringComparison.Ordinal)
            && !scheme.StartsWith('.')
            && !scheme.EndsWith('.')
            && !scheme.Contains("..", StringComparison.Ordinal);
}

internal static class OAuthScopes
{
    public static string[] Split(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
}
