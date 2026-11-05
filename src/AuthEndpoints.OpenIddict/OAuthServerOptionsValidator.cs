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

        if (!IsPage(options.LoginUrl))
        {
            failures.Add("OAuthServerOptions.LoginUrl must be an absolute URI or a path starting with '/'.");
        }

        if (!IsPage(options.ConsentUrl))
        {
            failures.Add("OAuthServerOptions.ConsentUrl must be an absolute URI or a path starting with '/'.");
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

    private static void Positive(List<string> failures, TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero)
        {
            failures.Add($"OAuthServerOptions.{name} must be positive.");
        }
    }
}
