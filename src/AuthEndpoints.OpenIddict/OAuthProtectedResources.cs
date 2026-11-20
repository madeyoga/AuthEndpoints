using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.OpenIddict;

/// <summary>One protected resource metadata document (RFC 9728) and the URL clients fetch it from.</summary>
/// <param name="Resource">The resource indicator, as configured.</param>
/// <param name="Path">Where this app serves it, relative to <c>PathBase</c>: the root path, or the root path plus the resource's path.</param>
/// <param name="MetadataUrl">The absolute URL that challenges point at.</param>
internal sealed record ProtectedResourceDocument(
    string Resource,
    string? ResourceName,
    string[] Scopes,
    PathString Path,
    string MetadataUrl);

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

    /// <summary>The document served at <paramref name="path"/>, or <see langword="null"/>.</summary>
    public ProtectedResourceDocument? Find(PathString path)
        => Suffixed.FirstOrDefault(document => document.Path.Equals(path, StringComparison.Ordinal));

    public static OAuthProtectedResources Create(OAuthServerOptions options)
    {
        var settings = options.ProtectedResource;
        var allScopes = options.AllScopes().ToArray();
        var audience = new ProtectedResourceDocument(
            options.Audience!,
            settings.ResourceName,
            settings.Scopes.Count > 0 ? settings.Scopes.Distinct(StringComparer.Ordinal).ToArray() : allScopes,
            Root,
            new Uri(options.Issuer!, OAuthServerConstants.ProtectedResourceMetadataPath.TrimStart('/')).AbsoluteUri);

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
            var definition = Definition(options, resource);
            suffixed.Add(resource == options.Audience
                ? audience with { Path = path, MetadataUrl = url }
                : new ProtectedResourceDocument(
                    resource,
                    definition?.ResourceName,
                    definition is { Scopes.Count: > 0 } ? definition.Scopes.Distinct(StringComparer.Ordinal).ToArray() : allScopes,
                    path,
                    url));
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

    private static OAuthProtectedResourceDefinition? Definition(OAuthServerOptions options, string resource)
        => options.ProtectedResource.Resources.FirstOrDefault(definition => definition.Resource == resource);
}
