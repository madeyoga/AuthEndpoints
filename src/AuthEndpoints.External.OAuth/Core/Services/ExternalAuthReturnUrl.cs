using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Return-URL policy for external sign-in. Rooted paths are classified before
/// <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> because on Linux a leading
/// slash is an absolute file URI. Absolute URLs are allowed only when scheme, host,
/// and port match <see cref="ExternalAuthOptions.AllowedReturnUrlOrigins"/>.
/// </summary>
internal static class ExternalAuthReturnUrl
{
    public static string Resolve(
        string? returnUrl,
        string defaultReturnUrl,
        IReadOnlyList<string> allowedOrigins)
    {
        if (TryAccept(returnUrl, allowedOrigins, out var accepted))
        {
            return accepted;
        }

        if (IsRelativeLocalUrl(defaultReturnUrl))
        {
            return defaultReturnUrl;
        }

        return "/";
    }

    public static bool IsRelativeLocalUrl(string? url) =>
        TryClassify(url, out var rooted, out _) && rooted;

    internal static bool IsAllowedOriginEntry(string? origin)
    {
        if (string.IsNullOrWhiteSpace(origin)
            || !Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!IsHttp(uri) || string.IsNullOrEmpty(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        return uri.AbsolutePath is "" or "/";
    }

    private static bool TryAccept(string? url, IReadOnlyList<string> allowedOrigins, out string accepted)
    {
        accepted = "";
        if (!TryClassify(url, out var rooted, out var absolute))
        {
            return false;
        }

        if (rooted)
        {
            accepted = url!.Trim();
            return true;
        }

        if (absolute is null || !IsOriginAllowlisted(absolute, allowedOrigins))
        {
            return false;
        }

        accepted = absolute.AbsoluteUri;
        return true;
    }

    private static bool TryClassify(string? url, out bool rooted, out Uri? absolute)
    {
        rooted = false;
        absolute = null;

        if (string.IsNullOrEmpty(url) || HasIllegalCharacters(url))
        {
            return false;
        }

        var trimmed = url.Trim();
        if (trimmed.Length == 0
            || trimmed[0] == '~'
            || trimmed.StartsWith("//", StringComparison.Ordinal)
            || trimmed.Contains('\\', StringComparison.Ordinal))
        {
            return false;
        }

        if (IsRootedPath(trimmed))
        {
            rooted = true;
            return true;
        }

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
            && IsHttp(uri)
            && !string.IsNullOrEmpty(uri.Host)
            && string.IsNullOrEmpty(uri.UserInfo))
        {
            absolute = uri;
            return true;
        }

        return false;
    }

    private static bool IsRootedPath(string value)
    {
        if (value[0] != '/')
        {
            return false;
        }

        if (value.Length == 1)
        {
            return true;
        }

        return value[1] != '/' && value[1] != '\\';
    }

    private static bool HasIllegalCharacters(string url)
    {
        foreach (var c in url)
        {
            if (c < 0x20 || c == 0x7f)
            {
                return true;
            }
        }

        return url.Contains("%0d", StringComparison.OrdinalIgnoreCase)
            || url.Contains("%0a", StringComparison.OrdinalIgnoreCase)
            || url.Contains("%00", StringComparison.OrdinalIgnoreCase)
            || url.Contains("%09", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHttp(Uri uri) =>
        string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
        || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static bool IsOriginAllowlisted(Uri absolute, IReadOnlyList<string> allowedOrigins)
    {
        for (var i = 0; i < allowedOrigins.Count; i++)
        {
            var candidate = allowedOrigins[i];
            if (string.IsNullOrWhiteSpace(candidate)
                || !Uri.TryCreate(candidate.Trim(), UriKind.Absolute, out var allowed))
            {
                continue;
            }

            if (string.Equals(absolute.Scheme, allowed.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(absolute.Host, allowed.Host, StringComparison.OrdinalIgnoreCase)
                && absolute.Port == allowed.Port)
            {
                return true;
            }
        }

        return false;
    }
}
