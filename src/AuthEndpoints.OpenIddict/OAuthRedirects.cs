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
    {
        if (value is null || value.Length > 2048
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.IsNullOrEmpty(uri.UserInfo))
        {
            return false;
        }

        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return true;
        }

        // IsLoopback covers localhost, 127.0.0.0/8, and [::1].
        return uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
    }
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
