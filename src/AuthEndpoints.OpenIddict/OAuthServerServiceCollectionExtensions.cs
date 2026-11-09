using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;

namespace AuthEndpoints.OpenIddict;

/// <summary>Returned by <c>AddAuthEndpointsOpenIddict</c> for further configuration.</summary>
public sealed class OAuthServerBuilder
{
    internal OAuthServerBuilder(IServiceCollection services, OpenIddictBuilder openIddict)
    {
        Services = services;
        OpenIddict = openIddict;
    }

    public IServiceCollection Services { get; }

    /// <summary>The underlying OpenIddict builder, for settings this package does not cover.</summary>
    public OpenIddictBuilder OpenIddict { get; }

    /// <summary>Binds <see cref="OAuthServerOptions"/> from a configuration section, for example <c>OAuthServer</c>.</summary>
    public OAuthServerBuilder BindConfiguration(string sectionPath)
    {
        Services.AddOptions<OAuthServerOptions>().BindConfiguration(sectionPath);
        return this;
    }

    /// <summary>Replaces the default <see cref="IOAuthPrincipalFactory"/> (which puts the user id in <c>sub</c>).</summary>
    public OAuthServerBuilder AddPrincipalFactory<TFactory>()
        where TFactory : class, IOAuthPrincipalFactory
    {
        Services.RemoveAll<IOAuthPrincipalFactory>();
        Services.AddScoped<IOAuthPrincipalFactory, TFactory>();
        return this;
    }

    /// <summary>
    /// Shows who built a developer app on the consent card (<c>owner</c>). Without it, <c>owner</c> is always
    /// <see langword="null"/>: the package never reads the owner's email or user name itself.
    /// </summary>
    public OAuthServerBuilder AddDeveloperAppOwnerDisplay<TDisplay>()
        where TDisplay : class, IOAuthDeveloperAppOwnerDisplay
    {
        Services.RemoveAll<IOAuthDeveloperAppOwnerDisplay>();
        Services.AddScoped<IOAuthDeveloperAppOwnerDisplay, TDisplay>();
        return this;
    }
}

public static class OAuthServerServiceCollectionExtensions
{
    /// <summary>
    /// The default recipe: registers the OAuth 2.0 authorization server (authorization code + PKCE, rotating refresh
    /// tokens, revocation, metadata) with the safe defaults of <see cref="OAuthServerOptions"/>, local token validation,
    /// and the services the consent API and developer app API need (authorization and antiforgery).
    /// Set what only the host can decide: <see cref="OAuthServerOptions.Issuer"/>, <see cref="OAuthServerOptions.Audience"/>,
    /// <see cref="OAuthServerOptions.Scopes"/>, <see cref="OAuthServerOptions.LoginUrl"/>,
    /// <see cref="OAuthServerOptions.ConsentUrl"/>, and one <see cref="OAuthServerOptions.Certificates"/> source.
    /// Anonymous registration stays off unless <see cref="OAuthDynamicRegistrationOptions.Enabled"/> is set.
    /// Then call <c>modelBuilder.UseAuthEndpointsOpenIddict&lt;TUser&gt;()</c> in the DbContext,
    /// <c>app.MapOAuthServer()</c> after <c>UseAuthentication</c>, and, when <see cref="OAuthServerOptions.Clients"/>
    /// is used, <c>SeedOAuthClientsAsync()</c> after migrations.
    /// Use it instead of <see cref="AddAuthEndpointsOpenIddict{TUser, TContext}"/>, once per host.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type. It must derive from <c>IdentityUser&lt;TKey&gt;</c>.</typeparam>
    /// <typeparam name="TContext">The EF Core context that holds the OpenIddict, consent, and developer app tables.</typeparam>
    /// <returns>The builder, for <c>AddPrincipalFactory</c>, <c>AddDeveloperAppOwnerDisplay</c>, and OpenIddict settings.</returns>
    public static OAuthServerBuilder AddOAuthServer<TUser, TContext>(
        this IServiceCollection services,
        Action<OAuthServerOptions>? configure = null)
        where TUser : class
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);
        if (services.Any(descriptor => descriptor.ServiceType == typeof(OAuthServerMarker)))
        {
            throw new InvalidOperationException(
                "The OAuth server is already registered. Call AddOAuthServer<TUser, TContext>() once, and not together with AddAuthEndpointsOpenIddict<TUser, TContext>().");
        }

        // The consent and developer app routes require a signed-in user and a CSRF token for cookie callers.
        services.AddAuthorization();
        services.AddAntiforgery();
        return services.AddAuthEndpointsOpenIddict<TUser, TContext>(configure);
    }

    /// <summary>
    /// Adds an OpenIddict authorization server and local token validation, stored in <typeparamref name="TContext"/>.
    /// Authorization code + PKCE (S256 only), rotating refresh tokens, reference tokens, and a host consent page.
    /// Call <c>modelBuilder.UseAuthEndpointsOpenIddict&lt;TUser&gt;()</c> in the DbContext and
    /// <c>app.MapAuthEndpointsOpenIddict()</c> after <c>UseAuthentication</c>.
    /// </summary>
    /// <typeparam name="TUser">
    /// The Identity user type. It must derive from <c>IdentityUser&lt;TKey&gt;</c>; the key type of the consent table comes from it.
    /// Also used to re-check the user on every code exchange and refresh.
    /// </typeparam>
    /// <typeparam name="TContext">The EF Core context that holds the OpenIddict and consent tables.</typeparam>
    public static OAuthServerBuilder AddAuthEndpointsOpenIddict<TUser, TContext>(
        this IServiceCollection services,
        Action<OAuthServerOptions>? configure = null)
        where TUser : class
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);
        // Fails here, at registration, when TUser is not an IdentityUser<TKey>.
        var keyType = TypeHelper.FindKeyType(typeof(TUser));
        var optionsBuilder = services.AddOptions<OAuthServerOptions>();
        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }

        optionsBuilder.ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<OAuthServerOptions>, OAuthServerOptionsValidator>());
        services.TryAddSingleton(TimeProvider.System);
        services.AddHttpContextAccessor();
        services.TryAddScoped<IOAuthPrincipalFactory, UserIdOAuthPrincipalFactory>();
        services.TryAddScoped<IOAuthUserValidator, IdentityOAuthUserValidator<TUser>>();
        services.TryAddScoped<IOAuthUserProfiles, IdentityOAuthUserProfiles<TUser>>();
        // OpenID Connect amr: tell the sign-in cookie which method signed the user in. Inert without the openid scope.
        OAuthSignInMethodRegistration<TUser>.Register(services);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CookieAuthenticationOptions>, OAuthSignInMethodCookieEvents>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<SecurityStampValidatorOptions>, OAuthSignInMethodCookieEvents>());
        services.TryAddSingleton<IOAuthDeveloperAppOwnerDisplay, NoOAuthDeveloperAppOwnerDisplay>();
        services.TryAddScoped(typeof(IOAuthConsentService), typeof(OAuthConsentService<,>).MakeGenericType(typeof(TContext), keyType));
        var developerApps = typeof(OAuthDeveloperAppService<,>).MakeGenericType(typeof(TContext), keyType);
        services.TryAddScoped(developerApps);
        services.TryAddScoped(typeof(IOAuthDeveloperAppService), provider => provider.GetRequiredService(developerApps));
        services.TryAddScoped(typeof(IOAuthDeveloperAppGate), provider => provider.GetRequiredService(developerApps));
        services.TryAddSingleton(typeof(IOAuthServerCleanup), typeof(OAuthServerCleanup<,>).MakeGenericType(typeof(TContext), keyType));
        services.TryAddSingleton<OAuthRegistrationRateLimiter>();
        services.TryAddSingleton(typeof(OAuthServerMarker), typeof(OAuthServerMarker<,>).MakeGenericType(typeof(TContext), keyType));
        services.AddHostedService<OAuthServerCleanupService>();

        var openIddict = services.AddOpenIddict()
            .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<TContext>())
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris(OAuthServerConstants.AuthorizationEndpointPath.TrimStart('/'))
                    .SetTokenEndpointUris(OAuthServerConstants.TokenEndpointPath.TrimStart('/'))
                    .SetRevocationEndpointUris(OAuthServerConstants.RevocationEndpointPath.TrimStart('/'))
                    .SetConfigurationEndpointUris(OAuthServerConstants.AuthorizationServerMetadataPath.TrimStart('/'))
                    .AllowAuthorizationCodeFlow()
                    .AllowRefreshTokenFlow()
                    .RequireProofKeyForCodeExchange()
                    .SetRefreshTokenReuseLeeway(TimeSpan.Zero)
                    .UseReferenceAccessTokens()
                    .UseReferenceRefreshTokens();
                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough();
                options.AddEventHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>(builder =>
                {
                    builder.UseSingletonHandler<SkipDetachedAuthorizationResponse>();
                    builder.SetOrder(1_000_000);
                });
                options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(builder =>
                {
                    builder.UseScopedHandler<RevalidateGrantUser>();
                    // Before any token is generated for the code or refresh grant.
                    builder.SetOrder(OpenIddictServerHandlers.ValidateSignInDemand.Descriptor.Order + 500);
                });
                // RFC 8252 §7.3: any port on loopback IP redirect URIs. Takes the built-in check's place.
                options.RemoveEventHandler(OpenIddictServerHandlers.Authentication.ValidateClientRedirectUri.Descriptor);
                options.AddEventHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>(builder =>
                {
                    builder.AddFilter<OpenIddictServerHandlerFilters.RequireDegradedModeDisabled>();
                    builder.UseScopedHandler<ValidateClientRedirectUriWithLoopbackPorts>();
                    builder.SetOrder(OpenIddictServerHandlers.Authentication.ValidateClientRedirectUri.Descriptor.Order);
                });
                options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(builder =>
                {
                    builder.UseScopedHandler<RequireActiveDeveloperApp>();
                    builder.SetOrder(OpenIddictServerHandlers.ValidateSignInDemand.Descriptor.Order + 400);
                });
                options.AddEventHandler<OpenIddictServerEvents.HandleConfigurationRequestContext>(builder =>
                {
                    builder.UseSingletonHandler<AttachRegistrationMetadata>();
                    // After every built-in Attach* handler, so the endpoint URLs are final.
                    builder.SetOrder(OpenIddictServerHandlers.Discovery.AttachAdditionalMetadata.Descriptor.Order + 1_000);
                });
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                // Only Authorization: Bearer by default. A token in the URL or a form ends up in logs, proxies,
                // and browser history; QueryStringTokenPaths opts chosen prefixes (SignalR hubs) back in.
                options.UseAspNetCore()
                    .DisableAccessTokenExtractionFromQueryString()
                    .DisableAccessTokenExtractionFromBodyForm();
                options.AddEventHandler(ExtractAccessTokenFromAllowedQueryPaths.Descriptor);
                options.EnableAuthorizationEntryValidation();
            });

        services.AddOptions<OpenIddictServerOptions>()
            .Configure<IOptions<OAuthServerOptions>, IServiceProvider>((server, oauth, provider) =>
            {
                var settings = oauth.Value;
                var clock = provider.GetRequiredService<TimeProvider>();
                server.Issuer = settings.Issuer;
                server.TimeProvider = clock;
                server.AuthorizationCodeLifetime = settings.AuthorizationCodeLifetime;
                server.AccessTokenLifetime = settings.AccessTokenLifetime;
                server.RefreshTokenLifetime = settings.RefreshTokenLifetime;
                server.RefreshTokenReuseLeeway = TimeSpan.Zero;
                server.DisableResourceValidation = settings.DisableResourceValidation;
                server.IgnoreResourcePermissions = settings.IgnoreResourcePermissions;
                // OpenID Connect is opt-in: without the openid scope, openid is neither accepted nor advertised.
                server.Scopes.Remove(OpenIddictConstants.Scopes.OpenId);
                if (settings.OpenIdConnectEnabled)
                {
                    server.UserInfoEndpointUris.Add(Relative(OAuthServerConstants.UserInfoEndpointPath));
                    server.EndSessionEndpointUris.Add(Relative(OAuthServerConstants.EndSessionEndpointPath));
                    server.ConfigurationEndpointUris.Add(Relative(OAuthServerConstants.OpenIdConfigurationPath));
                    server.Claims.Add(OpenIddictConstants.Claims.AuthenticationMethodReference);
                    server.Claims.Add(OpenIddictConstants.Claims.Email);
                    server.Claims.Add(OAuthIdentityClaims.EmailVerified);
                }

                foreach (var scope in settings.AllScopes())
                {
                    server.Scopes.Add(scope);
                }

                foreach (var resource in settings.AllResources())
                {
                    if (Uri.TryCreate(resource, UriKind.Absolute, out var uri))
                    {
                        server.Resources.Add(uri);
                    }
                }

                OAuthServerCertificates.Apply(server, settings.Certificates, clock);
            })
            .PostConfigure(server =>
            {
                server.CodeChallengeMethods.Remove(OpenIddictConstants.CodeChallengeMethods.Plain);
                server.CodeChallengeMethods.Add(OpenIddictConstants.CodeChallengeMethods.Sha256);
                server.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
            });
        services.AddOptions<OpenIddictServerAspNetCoreOptions>()
            .Configure<IOptions<OAuthServerOptions>>((aspNetCore, oauth) =>
            {
                aspNetCore.DisableTransportSecurityRequirement = oauth.Value.DisableTransportSecurityRequirement;
                if (oauth.Value.OpenIdConnectEnabled)
                {
                    aspNetCore.EnableUserInfoEndpointPassthrough = true;
                    aspNetCore.EnableEndSessionEndpointPassthrough = true;
                }
            });
        services.AddOptions<OpenIddictValidationOptions>()
            .Configure<IOptions<OAuthServerOptions>, IServiceProvider>((validation, oauth, provider) =>
            {
                validation.TimeProvider = provider.GetRequiredService<TimeProvider>();
                foreach (var audience in oauth.Value.ValidationAudiences())
                {
                    if (!string.IsNullOrEmpty(audience))
                    {
                        validation.Audiences.Add(audience);
                    }
                }
            })
            .PostConfigure(validation => validation.TokenValidationParameters.ClockSkew = TimeSpan.Zero);

        return new OAuthServerBuilder(services, openIddict);
    }

    private static Uri Relative(string path) => new(path.TrimStart('/'), UriKind.Relative);

    /// <summary>The authentication scheme that validates access tokens issued by this server.</summary>
    public const string ValidationScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
}
