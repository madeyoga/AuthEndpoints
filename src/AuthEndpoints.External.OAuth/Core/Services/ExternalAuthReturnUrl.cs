using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.External.OAuth;

internal static class ExternalAuthReturnUrl
{
    public static string Resolve(
        string? returnUrl,
        string defaultReturnUrl,
        IReadOnlyList<string> allowedOrigins)
    {
        if (!string.IsNullOrEmpty(returnUrl) && IsAllowedReturnUrl(returnUrl, allowedOrigins))
        {
            return returnUrl;
        }

        return string.IsNullOrEmpty(defaultReturnUrl) ? "/" : defaultReturnUrl;
    }

    public static bool IsAllowedReturnUrl(string url, IReadOnlyList<string> allowedOrigins)
    {
        if (IsRelativeLocalUrl(url))
        {
            return true;
        }

        if (allowedOrigins.Count == 0)
        {
            return false;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var absolute))
        {
            return false;
        }

        var origin = absolute.GetLeftPart(UriPartial.Authority);
        return allowedOrigins.Any(allowed =>
            string.Equals(allowed.TrimEnd('/'), origin, StringComparison.OrdinalIgnoreCase)
            || string.Equals(allowed.TrimEnd('/'), absolute.GetLeftPart(UriPartial.Path).TrimEnd('/'), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Relative local path only (same rules as ASP.NET Core IsLocalUrl for relative URLs). Absolute URLs are rejected here.
    /// </summary>
    public static bool IsRelativeLocalUrl(string? url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }

        // Reject absolute URLs and protocol-relative URLs.
        if (Uri.TryCreate(url, UriKind.Absolute, out _))
        {
            return false;
        }

        if (url[0] == '/')
        {
            if (url.Length == 1)
            {
                return true;
            }

            if (url[1] != '/' && url[1] != '\\')
            {
                return true;
            }

            return false;
        }

        if (url[0] == '~' && url.Length > 1 && url[1] == '/')
        {
            return true;
        }

        return false;
    }
}
