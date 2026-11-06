using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace AuthEndpoints.OpenIddict;

public static class OAuthServerEndpointRouteBuilderExtensions
{
    /// <summary>
    /// The default recipe's map call. Maps the authorization server (<see cref="MapAuthEndpointsOpenIddict"/>:
    /// authorize, plus registration and protected resource metadata when they are enabled in
    /// <see cref="OAuthServerOptions"/>), the JSON consent API (<see cref="MapOAuthConsentEndpoints"/>), and the developer
    /// app API (<see cref="MapOAuthDeveloperAppEndpoints"/>). Turn a part off or move it in <paramref name="configure"/>.
    /// Use it instead of those calls, not together with them.
    /// Fails at once when the server is not registered or <c>UseAuthEndpointsOpenIddict&lt;TUser&gt;()</c> is missing from the model.
    /// It does not seed <see cref="OAuthServerOptions.Clients"/>: call <c>SeedOAuthClientsAsync()</c> after migrations.
    /// </summary>
    public static OAuthServerEndpoints MapOAuthServer(
        this IEndpointRouteBuilder endpoints,
        Action<OAuthServerEndpointOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var marker = endpoints.ServiceProvider.GetService<OAuthServerMarker>()
            ?? throw new InvalidOperationException("Call services.AddOAuthServer<TUser, TContext>() first.");
        var parts = new OAuthServerEndpointOptions();
        configure?.Invoke(parts);
        if (parts.ConsentApi)
        {
            RequireRootedPrefix(parts.ConsentPrefix, nameof(OAuthServerEndpointOptions.ConsentPrefix));
        }

        if (parts.DeveloperApps)
        {
            RequireRootedPrefix(parts.DeveloperAppsPrefix, nameof(OAuthServerEndpointOptions.DeveloperAppsPrefix));
        }

        // Validates OAuthServerOptions now instead of on the first request.
        _ = endpoints.ServiceProvider.GetRequiredService<IOptions<OAuthServerOptions>>().Value;
        marker.EnsureModel(endpoints.ServiceProvider);

        endpoints.MapAuthEndpointsOpenIddict();
        return new OAuthServerEndpoints(
            parts.ConsentApi ? MapOAuthConsentEndpoints(endpoints, parts.ConsentPrefix) : null,
            parts.DeveloperApps ? MapOAuthDeveloperAppEndpoints(endpoints, parts.DeveloperAppsPrefix) : null);
    }

    private static void RequireRootedPrefix(string? prefix, string name)
    {
        if (string.IsNullOrWhiteSpace(prefix) || !prefix.StartsWith('/') || prefix.StartsWith("//", StringComparison.Ordinal))
        {
            throw new ArgumentException($"OAuthServerEndpointOptions.{name} must be a rooted path, for example \"/oauth\".", "configure");
        }
    }

    /// <summary>
    /// Maps <c>GET /connect/authorize</c>, plus <c>POST /connect/register</c> and
    /// <c>GET /.well-known/oauth-protected-resource</c> when they are enabled, and <c>/connect/userinfo</c> and
    /// <c>/connect/logout</c> when the <c>openid</c> scope is configured.
    /// OpenIddict serves <c>/connect/token</c>, <c>/connect/revoke</c>, and
    /// <c>/.well-known/oauth-authorization-server</c> itself, plus <c>/.well-known/openid-configuration</c> and
    /// <c>/.well-known/jwks</c> with OpenID Connect.
    /// </summary>
    public static IEndpointRouteBuilder MapAuthEndpointsOpenIddict(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var marker = endpoints.ServiceProvider.GetService<OAuthServerMarker>()
            ?? throw new InvalidOperationException("Call services.AddAuthEndpointsOpenIddict<TUser, TContext>() first.");
        var settings = endpoints.ServiceProvider.GetRequiredService<IOptions<OAuthServerOptions>>().Value;

        marker.MapAuthorize(endpoints)
            .AllowAnonymous()
            .ExcludeFromDescription();

        if (settings.OpenIdConnectEnabled)
        {
            if (endpoints.ServiceProvider.GetService<OAuthSignInMethodAudit>()?.Unwrapped() is { Count: > 0 } unwrapped)
            {
                endpoints.ServiceProvider.GetService<ILoggerFactory>()?.CreateLogger("AuthEndpoints.OpenIddict").LogWarning(
                    "These sign-in completers were registered after AddOAuthServer, so ID tokens from their sign-ins have no amr: {Completers}. "
                    + "Register them before AddOAuthServer, or add an amr claim to the cookie yourself.",
                    string.Join(", ", unwrapped));
            }

            endpoints.MapMethods(OAuthServerConstants.UserInfoEndpointPath, [HttpMethods.Get, HttpMethods.Post], OAuthUserInfoEndpoint.HandleAsync)
                .AllowAnonymous()
                .DisableAntiforgery()
                .ExcludeFromDescription();
            endpoints.MapMethods(OAuthServerConstants.EndSessionEndpointPath, [HttpMethods.Get, HttpMethods.Post], OAuthEndSessionEndpoint.HandleAsync)
                .AllowAnonymous()
                .DisableAntiforgery()
                .ExcludeFromDescription();
        }

        if (settings.DynamicRegistration.Enabled)
        {
            endpoints.MapPost(OAuthServerConstants.RegistrationEndpointPath, OAuthRegistrationEndpoint.HandleAsync)
                .AllowAnonymous()
                .DisableAntiforgery()
                .WithName("RegisterOAuthClient")
                .WithSummary("Register a public OAuth client (RFC 7591)")
                .WithTags("OAuth");
        }

        if (settings.ProtectedResource.Enabled)
        {
            endpoints.MapGet(OAuthServerConstants.ProtectedResourceMetadataPath, ProtectedResource)
                .AllowAnonymous()
                .WithName("GetOAuthProtectedResource")
                .WithSummary("Protected resource metadata (RFC 9728)")
                .WithTags("OAuth");
        }

        return endpoints;
    }

    /// <summary>
    /// Maps a JSON consent API for the host's consent page: <c>GET {prefix}/requests/{id}</c>,
    /// <c>POST {prefix}/requests/{id}/approve</c>, and <c>POST {prefix}/requests/{id}/deny</c>.
    /// Approve uses the registered <see cref="IOAuthPrincipalFactory"/>. The POSTs require a CSRF token
    /// for cookie callers. For a custom approval (extra choices on the page), call <see cref="IOAuthConsentService"/> instead.
    /// </summary>
    public static RouteGroupBuilder MapOAuthConsentEndpoints(this IEndpointRouteBuilder endpoints, string prefix = "/oauth")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return OAuthConsentEndpoints.Map(endpoints, prefix);
    }

    /// <summary>
    /// Maps a JSON API for a developer console, where signed-in users register and manage the OAuth apps they own:
    /// <c>GET {prefix}</c>, <c>POST {prefix}</c>, <c>GET|PUT|DELETE {prefix}/{id}</c>, and <c>POST {prefix}/{id}/secret</c>.
    /// The writes require a CSRF token for cookie callers. Admin review is in <see cref="IOAuthDeveloperAppService"/>.
    /// </summary>
    public static RouteGroupBuilder MapOAuthDeveloperAppEndpoints(this IEndpointRouteBuilder endpoints, string prefix = "/oauth/apps")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        _ = endpoints.ServiceProvider.GetService<OAuthServerMarker>()
            ?? throw new InvalidOperationException("Call services.AddAuthEndpointsOpenIddict<TUser, TContext>() first.");
        return OAuthDeveloperAppEndpoints.Map(endpoints, prefix);
    }

    private static IResult ProtectedResource(IOptions<OAuthServerOptions> options)
    {
        var settings = options.Value;
        return Results.Json(new ProtectedResourceMetadata(
            settings.Audience!,
            [settings.Issuer!.AbsoluteUri],
            ["header"],
            settings.AllScopes().ToArray(),
            settings.ProtectedResource.ResourceName));
    }
}

/// <summary>Remembers the DbContext and key types so mapping does not need them again.</summary>
internal abstract class OAuthServerMarker
{
    public abstract RouteHandlerBuilder MapAuthorize(IEndpointRouteBuilder endpoints);

    /// <summary>Throws when the DbContext model lacks the tables added by <c>UseAuthEndpointsOpenIddict</c>. Builds the model only.</summary>
    public abstract void EnsureModel(IServiceProvider services);
}

internal sealed class OAuthServerMarker<TContext, TKey> : OAuthServerMarker
    where TContext : DbContext
    where TKey : IEquatable<TKey>
{
    public override void EnsureModel(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var model = scope.ServiceProvider.GetRequiredService<TContext>().Model;
        if (model.FindEntityType(typeof(OAuthRequest<TKey>)) is null
            || model.FindEntityType(typeof(OAuthDeveloperApp<TKey>)) is null
            || model.FindEntityType(typeof(global::OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication)) is null)
        {
            throw new InvalidOperationException(
                $"{typeof(TContext).Name} has no OAuth server tables for user key type {typeof(TKey).Name}. " +
                "Call modelBuilder.UseAuthEndpointsOpenIddict<TUser>() in OnModelCreating, with the same TUser as AddOAuthServer, then add a migration.");
        }
    }

    public override RouteHandlerBuilder MapAuthorize(IEndpointRouteBuilder endpoints)
        => endpoints.MapMethods(
            OAuthServerConstants.AuthorizationEndpointPath,
            [HttpMethods.Get, HttpMethods.Post],
            OAuthAuthorizeEndpoint<TContext, TKey>.HandleAsync)
            .DisableAntiforgery();
}

internal sealed record ProtectedResourceMetadata(
    [property: JsonPropertyName("resource")] string Resource,
    [property: JsonPropertyName("authorization_servers")] string[] AuthorizationServers,
    [property: JsonPropertyName("bearer_methods_supported")] string[] BearerMethodsSupported,
    [property: JsonPropertyName("scopes_supported")] string[] ScopesSupported,
    [property: JsonPropertyName("resource_name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ResourceName);

public static class OAuthServerApplicationBuilderExtensions
{
    /// <summary>
    /// Adds <c>WWW-Authenticate: Bearer resource_metadata="…"</c> to 401 responses on
    /// <see cref="OAuthProtectedResourceOptions.ChallengePaths"/>, so MCP-style clients can discover the server.
    /// Does nothing unless protected resource metadata is enabled.
    /// </summary>
    public static IApplicationBuilder UseOAuthResourceChallenge(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        var settings = app.ApplicationServices.GetRequiredService<IOptions<OAuthServerOptions>>().Value;
        if (!settings.ProtectedResource.Enabled)
        {
            return app;
        }

        var paths = settings.ProtectedResource.ChallengePaths.Select(path => new PathString(path)).ToArray();
        var metadata = new Uri(settings.Issuer!, OAuthServerConstants.ProtectedResourceMetadataPath.TrimStart('/')).AbsoluteUri;
        var parameter = $"resource_metadata=\"{metadata}\"";
        return app.Use(async (context, next) =>
        {
            if (paths.Length == 0 || paths.Any(path => context.Request.Path.StartsWithSegments(path)))
            {
                context.Response.OnStarting(() =>
                {
                    if (context.Response.StatusCode == StatusCodes.Status401Unauthorized)
                    {
                        context.Response.Headers.WWWAuthenticate = WithResourceMetadata(
                            context.Response.Headers.WWWAuthenticate.ToString(), parameter);
                    }

                    return Task.CompletedTask;
                });
            }

            await next(context);
        });
    }

    /// <summary>Creates or updates <see cref="OAuthServerOptions.Clients"/>. Run it after migrations, before the app starts serving.</summary>
    public static async Task SeedOAuthClientsAsync(this IServiceProvider services, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        await using var scope = services.CreateAsyncScope();
        var settings = scope.ServiceProvider.GetRequiredService<IOptions<OAuthServerOptions>>().Value;
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        foreach (var client in settings.Clients)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = client.ClientId,
                DisplayName = string.IsNullOrWhiteSpace(client.DisplayName) ? client.ClientId : client.DisplayName,
                ClientType = string.IsNullOrEmpty(client.ClientSecret)
                    ? OpenIddictConstants.ClientTypes.Public
                    : OpenIddictConstants.ClientTypes.Confidential,
                ClientSecret = string.IsNullOrEmpty(client.ClientSecret) ? null : client.ClientSecret,
                ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            };
            foreach (var redirect in client.RedirectUris.Distinct(StringComparer.Ordinal))
            {
                descriptor.RedirectUris.Add(new Uri(redirect));
            }

            if (settings.OpenIdConnectEnabled)
            {
                foreach (var redirect in client.PostLogoutRedirectUris.Distinct(StringComparer.Ordinal))
                {
                    descriptor.PostLogoutRedirectUris.Add(new Uri(redirect));
                }
            }

            OAuthClientPermissions.AddCodeFlow(
                descriptor,
                client.Scopes.Count > 0 ? client.Scopes : settings.Scopes,
                client.Resources.Count > 0 ? client.Resources : settings.AllResources());

            var existing = await applications.FindByClientIdAsync(client.ClientId!, cancellationToken);
            if (existing is null)
            {
                await applications.CreateAsync(descriptor, cancellationToken);
            }
            else
            {
                await applications.UpdateAsync(existing, descriptor, cancellationToken);
            }
        }
    }

    internal static string WithResourceMetadata(string existing, string parameter)
    {
        if (string.IsNullOrWhiteSpace(existing))
        {
            return "Bearer " + parameter;
        }

        if (existing.Contains("resource_metadata=", StringComparison.Ordinal))
        {
            return existing;
        }

        var trimmed = existing.Trim();
        if (trimmed.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
        {
            return "Bearer " + parameter;
        }

        if (trimmed.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed + ", " + parameter;
        }

        // Another scheme challenged. Offer Bearer as well.
        return trimmed + ", Bearer " + parameter;
    }
}
