using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;

namespace AuthEndpoints.Identity;

internal static class ConfirmEmailRedirect
{
    public static string? TryResolve(
        string? configuredUri,
        IReadOnlyList<string> allowedOrigins,
        bool allowHttp,
        string requestScheme,
        HostString requestHost)
    {
        Kind kind = Inspect(configuredUri, out string trimmed, out Uri? absolute);
        return kind switch
        {
            Kind.RootedPath => ResolveRootedPath(trimmed, requestScheme, requestHost),
            Kind.Absolute => ResolveAbsolute(absolute!, allowedOrigins, allowHttp),
            _ => null
        };
    }

    public static string WithQuery(string uri, bool succeeded, bool isChangeEmail)
    {
        var parsed = new Uri(uri, UriKind.Absolute);
        Dictionary<string, StringValues> existing = QueryHelpers.ParseQuery(parsed.Query);
        var pairs = new List<KeyValuePair<string, string?>>();

        foreach (KeyValuePair<string, StringValues> pair in existing)
        {
            if (pair.Key.Equals("status", StringComparison.OrdinalIgnoreCase)
                || pair.Key.Equals("flow", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (string? value in pair.Value)
            {
                pairs.Add(new KeyValuePair<string, string?>(pair.Key, value));
            }
        }

        pairs.Add(new KeyValuePair<string, string?>("status", succeeded ? "confirmed" : "failed"));
        pairs.Add(new KeyValuePair<string, string?>("flow", isChangeEmail ? "change-email" : "confirm"));

        var builder = new UriBuilder(parsed)
        {
            Query = QueryString.Create(pairs).ToString().TrimStart('?')
        };

        return builder.Uri.AbsoluteUri;
    }

    internal static bool IsIllegal(string? configuredUri) =>
        Inspect(configuredUri, out _, out _) == Kind.Illegal;

    internal static bool TryGetAbsolute(string? configuredUri, out Uri absolute)
    {
        if (Inspect(configuredUri, out _, out Uri? uri) == Kind.Absolute)
        {
            absolute = uri!;
            return true;
        }

        absolute = null!;
        return false;
    }

    internal static bool IsOriginAllowlisted(Uri absolute, IReadOnlyList<string> allowedOrigins)
    {
        for (int i = 0; i < allowedOrigins.Count; i++)
        {
            string candidate = allowedOrigins[i];
            if (string.IsNullOrWhiteSpace(candidate)
                || !Uri.TryCreate(candidate.Trim(), UriKind.Absolute, out Uri? allowed))
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

    internal static IReadOnlyList<string> AsReadOnlyOrigins(IList<string> origins) =>
        origins as IReadOnlyList<string> ?? origins.ToList();

    private enum Kind
    {
        Unset,
        RootedPath,
        Absolute,
        Illegal
    }

    private static Kind Inspect(string? configuredUri, out string trimmed, out Uri? absolute)
    {
        trimmed = configuredUri?.Trim() ?? string.Empty;
        absolute = null;

        if (trimmed.Length == 0)
        {
            return Kind.Unset;
        }

        if (trimmed.StartsWith("//", StringComparison.Ordinal))
        {
            return Kind.Illegal;
        }

        if (IsRootedPath(trimmed))
        {
            return Kind.RootedPath;
        }

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? uri)
            && (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            && !string.IsNullOrEmpty(uri.Host))
        {
            absolute = uri;
            return Kind.Absolute;
        }

        return Kind.Illegal;
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

    private static string? ResolveRootedPath(string path, string requestScheme, HostString requestHost)
    {
        if (string.IsNullOrWhiteSpace(requestScheme) || !requestHost.HasValue)
        {
            return null;
        }

        string origin = $"{requestScheme}://{requestHost}";
        if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? originUri))
        {
            return null;
        }

        return new Uri(originUri, path).AbsoluteUri;
    }

    private static string? ResolveAbsolute(Uri absolute, IReadOnlyList<string> allowedOrigins, bool allowHttp)
    {
        if (string.Equals(absolute.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && !allowHttp)
        {
            return null;
        }

        if (allowedOrigins.Count == 0 || !IsOriginAllowlisted(absolute, allowedOrigins))
        {
            return null;
        }

        return absolute.AbsoluteUri;
    }
}
