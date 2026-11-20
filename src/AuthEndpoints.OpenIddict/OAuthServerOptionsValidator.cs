using Microsoft.Extensions.Options;

namespace AuthEndpoints.OpenIddict;

/// <summary>Fails startup when the server is missing a required setting.</summary>
public sealed class OAuthServerOptionsValidator : IValidateOptions<OAuthServerOptions>
{
    public ValidateOptionsResult Validate(string? name, OAuthServerOptions options)
    {
        var failures = new List<string>();

        if (options.Issuer is not { IsAbsoluteUri: true } issuer)
        {
            failures.Add("OAuthServerOptions.Issuer must be an absolute URI.");
        }
        else
        {
            if (!string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment))
            {
                failures.Add("OAuthServerOptions.Issuer must not have a query or fragment.");
            }

            if (issuer.Scheme != Uri.UriSchemeHttps && !options.DisableTransportSecurityRequirement)
            {
                failures.Add("OAuthServerOptions.Issuer must use https unless DisableTransportSecurityRequirement is true.");
            }
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            failures.Add("OAuthServerOptions.Audience is required.");
        }

        foreach (var resource in options.AllResources())
        {
            if (!IsResourceIndicator(resource))
            {
                failures.Add($"Resource '{resource}' must be an absolute URI with no fragment.");
            }
        }

        var configuredResources = options.AllResources().ToHashSet(StringComparer.Ordinal);
        foreach (var audience in options.AcceptedAudiences)
        {
            if (!configuredResources.Contains(audience))
            {
                failures.Add($"AcceptedAudiences entry '{audience}' is not Audience or in AdditionalResources.");
            }
        }

        foreach (var scope in options.Scopes)
        {
            if (string.IsNullOrWhiteSpace(scope) || scope.Any(char.IsWhiteSpace) || scope.Contains('"') || scope.Contains('\\'))
            {
                failures.Add($"Scope '{scope}' is not a valid scope token.");
            }
        }

        var all = options.AllScopes().ToHashSet(StringComparer.Ordinal);
        foreach (var scope in options.DefaultScopes)
        {
            if (!all.Contains(scope))
            {
                failures.Add($"Default scope '{scope}' is not in OAuthServerOptions.Scopes.");
            }
        }

        var described = new HashSet<string>(StringComparer.Ordinal);
        foreach (var definition in options.ScopeDefinitions)
        {
            if (string.IsNullOrWhiteSpace(definition.Name))
            {
                failures.Add("Every ScopeDefinitions entry needs a Name.");
                continue;
            }

            if (!all.Contains(definition.Name))
            {
                failures.Add($"ScopeDefinitions entry '{definition.Name}' is not in OAuthServerOptions.Scopes.");
            }

            if (!described.Add(definition.Name))
            {
                failures.Add($"ScopeDefinitions lists '{definition.Name}' twice.");
            }

            foreach (var culture in definition.DisplayNames.Keys.Concat(definition.Descriptions.Keys))
            {
                if (!OAuthScopeDescriptions.IsCultureName(culture))
                {
                    failures.Add($"ScopeDefinitions entry '{definition.Name}' has text for '{culture}', which is not a culture name such as 'fr' or 'pt-BR'.");
                }
            }
        }

        if (!IsPage(options.LoginUrl))
        {
            failures.Add("OAuthServerOptions.LoginUrl must be an absolute URI or a path starting with '/'.");
        }

        if (!IsPage(options.ConsentUrl))
        {
            failures.Add("OAuthServerOptions.ConsentUrl must be an absolute URI or a path starting with '/'.");
        }

        if (options.LogoutUrl is not null && !IsPage(options.LogoutUrl))
        {
            failures.Add("OAuthServerOptions.LogoutUrl must be an absolute URI or a path starting with '/'.");
        }

        if (string.IsNullOrWhiteSpace(options.LoginReturnUrlParameter) || string.IsNullOrWhiteSpace(options.ConsentRequestParameter))
        {
            failures.Add("LoginReturnUrlParameter and ConsentRequestParameter must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(options.AuthenticationScheme) || string.IsNullOrWhiteSpace(options.UserIdClaimType))
        {
            failures.Add("AuthenticationScheme and UserIdClaimType must not be empty.");
        }

        Positive(failures, options.AuthorizationCodeLifetime, nameof(options.AuthorizationCodeLifetime));
        Positive(failures, options.AccessTokenLifetime, nameof(options.AccessTokenLifetime));
        Positive(failures, options.RefreshTokenLifetime, nameof(options.RefreshTokenLifetime));
        Positive(failures, options.ConsentLifetime, nameof(options.ConsentLifetime));
        Positive(failures, options.PruneAfter, nameof(options.PruneAfter));
        if (options.TokenRateLimit.Enabled)
        {
            if (options.TokenRateLimit.PermitLimit < 1)
            {
                failures.Add("OAuthServerOptions.TokenRateLimit.PermitLimit must be at least 1.");
            }

            if (options.TokenRateLimit.Window <= TimeSpan.Zero)
            {
                failures.Add("OAuthServerOptions.TokenRateLimit.Window must be positive.");
            }
        }

        var certificates = options.Certificates;
        var sources = 0;
        if (!string.IsNullOrWhiteSpace(certificates.Path))
        {
            sources++;
        }

        if (certificates.SigningCertificate is not null || certificates.EncryptionCertificate is not null)
        {
            sources++;
            if (certificates.SigningCertificate is null || certificates.EncryptionCertificate is null)
            {
                failures.Add("Set both Certificates.SigningCertificate and Certificates.EncryptionCertificate.");
            }
        }

        if (certificates.UseEphemeralKeys)
        {
            sources++;
        }

        if (sources != 1)
        {
            failures.Add("Set exactly one of Certificates.Path, Certificates.SigningCertificate/EncryptionCertificate, or Certificates.UseEphemeralKeys.");
        }

        var registration = options.DynamicRegistration;
        if (registration.Enabled)
        {
            if (registration.PermitsPerMinute < 1)
            {
                failures.Add("DynamicRegistration.PermitsPerMinute must be at least 1.");
            }

            if (registration.MaxClientNameLength < 1 || registration.MaxRedirectUris < 1)
            {
                failures.Add("DynamicRegistration.MaxClientNameLength and MaxRedirectUris must be at least 1.");
            }

            Positive(failures, registration.UnusedClientLifetime, "DynamicRegistration.UnusedClientLifetime");
        }

        var documents = options.ClientMetadataDocuments;
        if (documents.Enabled)
        {
            Positive(failures, documents.FetchTimeout, "ClientMetadataDocuments.FetchTimeout");
            Positive(failures, documents.MinCacheDuration, "ClientMetadataDocuments.MinCacheDuration");
            Positive(failures, documents.MaxCacheDuration, "ClientMetadataDocuments.MaxCacheDuration");
            if (documents.MaxCacheDuration < documents.MinCacheDuration)
            {
                failures.Add("ClientMetadataDocuments.MaxCacheDuration must not be shorter than MinCacheDuration.");
            }

            if (documents.MaxDocumentBytes is < 256 or > 64 * 1024)
            {
                failures.Add("ClientMetadataDocuments.MaxDocumentBytes must be between 256 and 65536.");
            }

            if (documents.FetchesPerMinute < 1)
            {
                failures.Add("ClientMetadataDocuments.FetchesPerMinute must be at least 1.");
            }

            if (registration.MaxClientNameLength < 1 || registration.MaxRedirectUris < 1)
            {
                failures.Add("DynamicRegistration.MaxClientNameLength and MaxRedirectUris must be at least 1; client metadata documents use them too.");
            }
        }

        foreach (var host in documents.AllowedHosts.Concat(documents.DeniedHosts))
        {
            if (!OAuthClientMetadataHosts.IsValidPattern(host))
            {
                failures.Add($"ClientMetadataDocuments host '{host}' must be a host name, such as 'client.example.com', or '*.example.com'.");
            }
        }

        foreach (var scope in registration.AllowedScopes)
        {
            if (!all.Contains(scope))
            {
                failures.Add($"DynamicRegistration.AllowedScopes entry '{scope}' is not in OAuthServerOptions.Scopes.");
            }
        }

        if (options.ProtectedResource.Enabled)
        {
            ValidateProtectedResources(failures, options, all);
        }

        foreach (var path in options.QueryStringTokenPaths)
        {
            if (!IsPathPrefix(path))
            {
                failures.Add($"QueryStringTokenPaths entry '{path}' must be a path that starts with '/', such as '/hubs', with no trailing '/', query, or fragment.");
            }
        }

        if (options.DeveloperApps.MaxAppsPerUser < 1 || options.DeveloperApps.MaxRedirectUris < 1)
        {
            failures.Add("DeveloperApps.MaxAppsPerUser and MaxRedirectUris must be at least 1.");
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var client in options.Clients)
        {
            if (string.IsNullOrWhiteSpace(client.ClientId))
            {
                failures.Add("Every entry in OAuthServerOptions.Clients needs a ClientId.");
                continue;
            }

            if (client.ClientId.Length > 64)
            {
                failures.Add($"Client id '{client.ClientId}' is longer than 64 characters.");
            }

            if (!ids.Add(client.ClientId))
            {
                failures.Add($"Client '{client.ClientId}' is listed twice.");
            }

            if (client.RedirectUris.Count == 0)
            {
                failures.Add($"Client '{client.ClientId}' needs at least one redirect URI.");
            }

            foreach (var redirect in client.RedirectUris)
            {
                if (!Uri.TryCreate(redirect, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
                {
                    failures.Add($"Client '{client.ClientId}' redirect URI '{redirect}' must be absolute with no fragment.");
                }
            }

            foreach (var redirect in client.PostLogoutRedirectUris)
            {
                if (!Uri.TryCreate(redirect, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
                {
                    failures.Add($"Client '{client.ClientId}' post-logout redirect URI '{redirect}' must be absolute with no fragment.");
                }
            }

            foreach (var scope in client.Scopes)
            {
                if (!all.Contains(scope))
                {
                    failures.Add($"Client '{client.ClientId}' scope '{scope}' is not configured.");
                }
            }

            var resources = options.AllResources().ToHashSet(StringComparer.Ordinal);
            foreach (var resource in client.Resources)
            {
                if (!resources.Contains(resource))
                {
                    failures.Add($"Client '{client.ClientId}' resource '{resource}' is not configured.");
                }
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateProtectedResources(List<string> failures, OAuthServerOptions options, HashSet<string> scopes)
    {
        var settings = options.ProtectedResource;
        foreach (var scope in settings.Scopes)
        {
            if (!scopes.Contains(scope))
            {
                failures.Add($"ProtectedResource.Scopes entry '{scope}' is not in OAuthServerOptions.Scopes.");
            }
        }

        var accepted = options.ValidationAudiences().ToHashSet(StringComparer.Ordinal);
        var sharedPath = OAuthProtectedResources.SuffixedResources(options)
            .GroupBy(item => item.Path.Value, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .SelectMany(group => group.Select(item => item.Resource))
            .ToHashSet(StringComparer.Ordinal);
        var described = new HashSet<string>(StringComparer.Ordinal);
        var challengePaths = new HashSet<string>(settings.ChallengePaths, StringComparer.Ordinal);
        foreach (var definition in settings.Resources)
        {
            if (string.IsNullOrWhiteSpace(definition.Resource))
            {
                failures.Add("Every ProtectedResource.Resources entry needs a Resource.");
                continue;
            }

            var resource = definition.Resource;
            if (!described.Add(resource))
            {
                failures.Add($"ProtectedResource.Resources lists '{resource}' twice.");
            }

            if (resource == options.Audience)
            {
                failures.Add($"ProtectedResource.Resources entry '{resource}' is Audience. Describe it with ProtectedResource.ResourceName, Scopes, and ChallengePaths.");
            }
            else if (!accepted.Contains(resource))
            {
                failures.Add($"ProtectedResource.Resources entry '{resource}' is not in AcceptedAudiences.");
            }
            else if (OAuthProtectedResources.ResourcePath(resource) is null)
            {
                failures.Add($"ProtectedResource.Resources entry '{resource}' needs a path and no query, for example 'https://host/mcp'.");
            }
            else if (sharedPath.Contains(resource))
            {
                failures.Add($"ProtectedResource.Resources entry '{resource}' has the same path as another accepted resource, so its metadata cannot be served. Give each resource its own path.");
            }

            foreach (var scope in definition.Scopes)
            {
                if (!scopes.Contains(scope))
                {
                    failures.Add($"ProtectedResource.Resources entry '{resource}' scope '{scope}' is not in OAuthServerOptions.Scopes.");
                }
            }

            foreach (var path in definition.ChallengePaths)
            {
                if (!IsPathPrefix(path))
                {
                    failures.Add($"ProtectedResource.Resources entry '{resource}' challenge path '{path}' must start with '/', such as '/mcp', with no trailing '/', query, or fragment.");
                }
                else if (!challengePaths.Add(path))
                {
                    failures.Add($"Challenge path '{path}' is listed more than once in ProtectedResource.");
                }
            }
        }
    }

    internal static bool IsResourceIndicator(string? value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) && string.IsNullOrEmpty(uri.Fragment);

    private static bool IsPage(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (value.StartsWith('/') && !value.StartsWith("//", StringComparison.Ordinal) && !value.StartsWith("/\\", StringComparison.Ordinal))
        {
            return true;
        }

        return Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);
    }

    // "/" alone matches nothing but the root with PathString.StartsWithSegments, and a trailing "/" would skip the
    // prefix itself, so both are refused rather than silently doing something other than what they look like.
    private static bool IsPathPrefix(string? value)
        => !string.IsNullOrWhiteSpace(value)
            && value.Length > 1
            && value[0] == '/'
            && value[1] != '/'
            && !value.EndsWith('/')
            && value.IndexOfAny(['?', '#', '\\']) < 0
            && !value.Any(char.IsWhiteSpace);

    private static void Positive(List<string> failures, TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero)
        {
            failures.Add($"OAuthServerOptions.{name} must be positive.");
        }
    }
}
