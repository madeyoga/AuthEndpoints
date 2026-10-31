using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Sessions;

internal sealed class ActiveSessionsModule;

public static class ActiveSessionServiceCollectionExtensions
{
    /// <summary>
    /// Turns on active session tracking for cookie and JWT sign-ins: every successful sign-in records a
    /// session that the user can list and revoke (<see cref="ActiveSessionEndpointRouteBuilderExtensions.MapActiveSessionEndpoints{TUser}"/>).
    /// Also call <see cref="ActiveSessionModelBuilderExtensions.UseActiveSessions"/> in <c>OnModelCreating</c>.
    /// With JWT, call this after <c>AddJwtEndpoints</c> and any custom token services.
    /// Identity bearer tokens are not supported and fail startup.
    /// </summary>
    public static IServiceCollection AddActiveSessions<TUser, TContext>(
        this IServiceCollection services,
        Action<ActiveSessionOptions>? configure = null)
        where TUser : class
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);
        if (services.HasModule<ActiveSessionsModule>())
        {
            return services;
        }

        services.AddModule<ActiveSessionsModule>();

        var options = services.AddOptions<ActiveSessionOptions>();
        if (configure is not null)
        {
            options.Configure(configure);
        }

        options
            .Validate(o => o.LastSeenUpdateInterval >= TimeSpan.Zero, "ActiveSessions: LastSeenUpdateInterval must not be negative.")
            .Validate(o => o.CleanupInterval > TimeSpan.Zero, "ActiveSessions: CleanupInterval must be positive.")
            .ValidateOnStart();

        services.TryAddSingleton(TimeProvider.System);
        services.AddHttpContextAccessor();
        services.TryAddScoped<IActiveSessionStore, ActiveSessionStore<TContext>>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<CookieAuthenticationOptions>, ActiveSessionCookieEvents>());
        services.AddHostedService<ActiveSessionHostedService<TContext>>();
        services.AddTransient<IStartupFilter, ActiveSessionStartupFilter<TContext>>();

        Decorate<IRefreshTokenService>(services, (sp, inner) => new ActiveSessionRefreshTokenService(
            inner,
            sp.GetRequiredService<IActiveSessionStore>(),
            sp.GetRequiredService<Microsoft.AspNetCore.Http.IHttpContextAccessor>()));
        Decorate<IAccessTokenGenerator>(services, (sp, inner) => new ActiveSessionAccessTokenGenerator(
            inner,
            sp.GetRequiredService<Microsoft.AspNetCore.Http.IHttpContextAccessor>()));

        return services;
    }

    private static void Decorate<TService>(
        IServiceCollection services,
        Func<IServiceProvider, TService, TService> decorate)
        where TService : class
    {
        for (var i = services.Count - 1; i >= 0; i--)
        {
            var descriptor = services[i];
            if (descriptor.ServiceType != typeof(TService) || descriptor.IsKeyedService)
            {
                continue;
            }

            services[i] = ServiceDescriptor.Describe(
                typeof(TService),
                sp => decorate(sp, (TService)CreateInner(sp, descriptor)),
                descriptor.Lifetime);
            return;
        }
    }

    private static object CreateInner(IServiceProvider sp, ServiceDescriptor descriptor)
    {
        if (descriptor.ImplementationInstance is { } instance)
        {
            return instance;
        }

        if (descriptor.ImplementationFactory is { } factory)
        {
            return factory(sp);
        }

        return ActivatorUtilities.CreateInstance(sp, descriptor.ImplementationType!);
    }
}
