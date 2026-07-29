using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.External;

internal static class ExternalAuthReturnUrl
{
    public static string Resolve(HttpContext httpContext, string? returnUrl, string defaultReturnUrl)
    {
        if (!string.IsNullOrEmpty(returnUrl) && IsLocalUrl(httpContext, returnUrl))
        {
            return returnUrl;
        }

        return string.IsNullOrEmpty(defaultReturnUrl) ? "/" : defaultReturnUrl;
    }

    private static bool IsLocalUrl(HttpContext httpContext, string url)
    {
        // Absolute URLs to this host are treated as local for OAuth returnUrl convenience.
        if (Uri.TryCreate(url, UriKind.Absolute, out var absolute))
        {
            return string.Equals(absolute.Host, httpContext.Request.Host.Host, StringComparison.OrdinalIgnoreCase);
        }

        // Same rules as ASP.NET Core's UrlHelper.IsLocalUrl for relative paths.
        if (string.IsNullOrEmpty(url))
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
