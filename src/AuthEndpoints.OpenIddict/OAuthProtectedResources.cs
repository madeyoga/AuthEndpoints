using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.OpenIddict;

/// <summary>One protected resource metadata document (RFC 9728) and the URL clients fetch it from.</summary>
/// <param name="Resource">The resource indicator, as configured.</param>
/// <param name="ResourceName">The <c>resource_name</c>, if any.</param>
/// <param name="Scopes">The <c>scopes_supported</c>.</param>
/// <param name="Path">
/// The RFC 9728 §3.1 path from the host root: the root path, or the root path plus the resource's whole path, such as
/// <c>/.well-known/oauth-protected-resource/app/mcp</c>. A proxy that forwards that URL unchanged to the app reaches it.
/// </param>
/// <param name="MetadataUrl">The absolute URL that challenges point at.</param>
/// <param name="AppPath">
/// The same document relative to the app's <c>PathBase</c>, taken as the <see cref="OAuthServerOptions.Issuer"/> path:
/// for an issuer <c>https://host/app/</c> and a resource <c>https://host/app/mcp</c>, <c>/.well-known/oauth-protected-resource/mcp</c>.
/// Equal to <paramref name="Path"/> when the issuer has no path, or the resource is not under it.
/// </param>
internal sealed record ProtectedResourceDocument(
    string Resource,
    string? ResourceName,
    string[] Scopes,
    PathString Path,
    string MetadataUrl,
    PathString AppPath);

/// <summary>
/// Builds the protected resource metadata documents and challenge targets from <see cref="OAuthServerOptions"/>.
/// Every value comes from configuration. The request <c>Host</c> header is never read.
/// </summary>
internal sealed class OAuthProtectedResources
{
    private static readonly PathString Root = new(OAuthServerConstants.ProtectedResourceMetadataPath);

    private OAuthProtectedResources(
        ProtectedResourceDocument audience,
        IReadOnlyList<ProtectedResourceDocument> suffixed,
        IReadOnlyList<(PathString Prefix, string MetadataUrl)> challenges,
        bool challengeEveryOtherPath)
    {
        Audience = audience;
        Suffixed = suffixed;
        Challenges = challenges;
        ChallengeEveryOtherPath = challengeEveryOtherPath;
    }

    /// <summary>The root document, for <see cref="OAuthServerOptions.Audience"/>.</summary>
    public ProtectedResourceDocument Audience { get; }

    /// <summary>The path-suffixed documents, one per accepted resource with a path that no other accepted resource shares.</summary>
    public IReadOnlyList<ProtectedResourceDocument> Suffixed { get; }

    /// <summary>Challenge path prefixes and the metadata URL each points at, longest first.</summary>
    public IReadOnlyList<(PathString Prefix, string MetadataUrl)> Challenges { get; }

    /// <summary>Whether a path that no prefix matches points at the root document (no top-level challenge paths).</summary>
    public bool ChallengeEveryOtherPath { get; }

    /// <summary>The metadata URL for a 401 on <paramref name="path"/>, or <see langword="null"/> for none.</summary>
    public string? ChallengeFor(PathString path)
    {
        foreach (var (prefix, url) in Challenges)
        {
            if (path.StartsWithSegments(prefix))
            {
                return url;
            }
        }

        return ChallengeEveryOtherPath ? Audience.MetadataUrl : null;
    }

    /// <summary>
    /// The document for a request, or <see langword="null"/>. A request matches when <paramref name="pathBase"/> plus
    /// <paramref name="path"/> is the RFC 9728 location (a proxy forwarded it unchanged), or when <paramref name="path"/>
    /// alone is the location relative to the app (<c>{PathBase}/.well-known/oauth-protected-resource/{rest}</c>).
    /// </summary>
    public ProtectedResourceDocument? Find(PathString pathBase, PathString path)
    {
        var full = pathBase.Add(path);
        return Suffixed.FirstOrDefault(document => document.Path.Equals(full, StringComparison.Ordinal))
            ?? Suffixed.FirstOrDefault(document => document.AppPath.Equals(path, StringComparison.Ordinal));
    }

    public static OAuthProtectedResources Create(OAuthServerOptions options)
    {
        var settings = options.ProtectedResource;
        var allScopes = options.AllScopes().ToArray();
        var audience = new ProtectedResourceDocument(
            options.Audience!,
            settings.ResourceName,
            settings.Scopes.Count > 0 ? settings.Scopes.Distinct(StringComparer.Ordinal).ToArray() : allScopes,
            Root,
            new Uri(options.Issuer!, OAuthServerConstants.ProtectedResourceMetadataPath.TrimStart('/')).AbsoluteUri,
            Root);

        var suffixed = new List<ProtectedResourceDocument>();
        foreach (var group in SuffixedResources(options).GroupBy(item => item.Path.Value, StringComparer.Ordinal))
        {
            // Without the Host header, two resources with the same path cannot be told apart. Serve neither;
            // the options validator refuses this when a Resources entry names one of them.
            if (group.Count() != 1)
            {
                continue;
            }

            var (resource, path, url) = group.Single();
            var appPath = AppRelativePath(options, resource) is { } relative ? Root.Add(new PathString(relative)) : path;
            var definition = Definition(options, resource);
            suffixed.Add(resource == options.Audience
                ? audience with { Path = path, MetadataUrl = url, AppPath = appPath }
                : new ProtectedResourceDocument(
                    resource,
                    definition?.ResourceName,
                    definition is { Scopes.Count: > 0 } ? definition.Scopes.Distinct(StringComparer.Ordinal).ToArray() : allScopes,
                    path,
                    url,
                    appPath));
        }

        var challenges = settings.ChallengePaths
            .Select(prefix => (Prefix: new PathString(prefix), audience.MetadataUrl))
            .Concat(settings.Resources.SelectMany(definition => definition.ChallengePaths.Select(prefix => (
                Prefix: new PathString(prefix),
                MetadataUrl: suffixed.FirstOrDefault(document => document.Resource == definition.Resource)?.MetadataUrl ?? audience.MetadataUrl))))
            .OrderByDescending(item => item.Prefix.Value!.Length)
            .ToList();
        return new OAuthProtectedResources(audience, suffixed, challenges, settings.ChallengePaths.Count == 0);
    }

    /// <summary>
    /// Accepted resources with a path and no query, with their document path and RFC 9728 §3.1 metadata URL:
    /// <c>https://host/mcp</c> → <c>https://host/.well-known/oauth-protected-resource/mcp</c>.
    /// </summary>
    internal static IEnumerable<(string Resource, PathString Path, string MetadataUrl)> SuffixedResources(OAuthServerOptions options)
    {
        foreach (var resource in options.ValidationAudiences())
        {
            if (ResourcePath(resource) is { } path)
            {
                var uri = new Uri(resource);
                yield return (
                    resource,
                    Root.Add(new PathString(Uri.UnescapeDataString(path))),
                    uri.GetLeftPart(UriPartial.Authority) + OAuthServerConstants.ProtectedResourceMetadataPath + path);
            }
        }
    }

    /// <summary>The escaped path of a resource that can have a path-suffixed document, or <see langword="null"/>.</summary>
    internal static string? ResourcePath(string? resource)
        => Uri.TryCreate(resource, UriKind.Absolute, out var uri)
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment)
            && uri.AbsolutePath is { Length: > 1 } path
                ? path
                : null;

    /// <summary>
    /// The unescaped path of <paramref name="resource"/> relative to the <see cref="OAuthServerOptions.Issuer"/> path, such as
    /// <c>/mcp</c> for <c>https://host/app/mcp</c> under <c>https://host/app/</c>, or <see langword="null"/> when the issuer
    /// has no path, the resource is on another origin, or its path is not under the issuer path.
    /// </summary>
    internal static string? AppRelativePath(OAuthServerOptions options, string resource)
    {
        if (options.Issuer is not { } issuer || IssuerPath(issuer) is not { } prefix || ResourcePath(resource) is not { } path)
        {
            return null;
        }

        var uri = new Uri(resource);
        if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), issuer.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var unescaped = Uri.UnescapeDataString(path);
        return unescaped.Length > prefix.Length && unescaped.StartsWith(prefix + "/", StringComparison.Ordinal)
            ? unescaped[prefix.Length..]
            : null;
    }

    /// <summary>
    /// Accepted resources on the issuer's origin whose path is outside the issuer path, while the issuer has one. Their
    /// documents are reachable only through a proxy that forwards the RFC 9728 URL to this app unchanged.
    /// </summary>
    internal static IEnumerable<string> OutsideIssuerPath(OAuthServerOptions options)
    {
        if (options.Issuer is not { } issuer || IssuerPath(issuer) is null)
        {
            yield break;
        }

        var authority = issuer.GetLeftPart(UriPartial.Authority);
        foreach (var (resource, _, _) in SuffixedResources(options))
        {
            if (string.Equals(new Uri(resource).GetLeftPart(UriPartial.Authority), authority, StringComparison.OrdinalIgnoreCase)
                && AppRelativePath(options, resource) is null)
            {
                yield return resource;
            }
        }
    }

    /// <summary>The unescaped issuer path without its trailing <c>/</c>, such as <c>/app</c>, or <see langword="null"/> for the root.</summary>
    private static string? IssuerPath(Uri issuer)
        => Uri.UnescapeDataString(issuer.AbsolutePath).TrimEnd('/') is { Length: > 0 } path ? path : null;

    private static OAuthProtectedResourceDefinition? Definition(OAuthServerOptions options, string resource)
        => options.ProtectedResource.Resources.FirstOrDefault(definition => definition.Resource == resource);
}
