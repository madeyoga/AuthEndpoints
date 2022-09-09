using AuthEndpoints.Core.Endpoints;
using AuthEndpoints.Core.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.Core;

/// <summary>
/// Provides extensions to easily bootstrap authendpoints
/// </summary>
public static class ServiceCollectionExtensions
{
    internal static AuthEndpointsBuilder ConfigureServices<TUser, TContext>(IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        var keyType = TypeHelper.FindKeyType(typeof(TUser))!;
        services.AddAuthorization();

        //services.AddSingleton(typeof(IOptions<AuthEndpointsOptions>), Options.Create(endpointsOptions));

        services.TryAddScoped<IAuthenticator<TUser>, DefaultAuthenticator<TUser>>();

        services.TryAddSingleton<IEmailFactory, DefaultMessageFactory>();
        services.TryAddSingleton<IEmailSender, DefaultEmailSender>();

        services.AddEndpointsApiExplorer();

        var identityBuilder = services.AddIdentityCore<TUser>()
            .AddEntityFrameworkStores<TContext>()
            .AddDefaultTokenProviders();

        return new AuthEndpointsBuilder(keyType, typeof(TUser), services);
    }

    /// <summary>
    /// Adds the AuthEndpoints core services
    /// </summary>
    /// <typeparam name="TUserKey"></typeparam>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns>An <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpointsCore<TUser, TContext>(this IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        return services.AddAuthEndpointsCore<TUser, TContext>(o => { });
    }

    /// <summary>
    /// Adds and configures the AuthEndpoints core system.
    /// </summary>
    /// <typeparam name="TUserKey">The type representing a User's primary key in the system.</typeparam>
    /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
    /// <param name="services">The services available in the application.</param>
    /// <param name="setup">An action to configure the <see cref="AuthEndpointsOptions"/>.</param>
    /// <returns>An <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpointsCore<TUser, TContext>(this IServiceCollection services, Action<AuthEndpointsOptions> setup)
        where TUser : class
        where TContext : DbContext
    {
        if (setup != null)
        {
            services.AddOptions<AuthEndpointsOptions>()
                .Configure(setup);
        }

        return ConfigureServices<TUser, TContext>(services);
    }

    /// <summary>
    /// Add endpoint definition
    /// </summary>
    /// <typeparam name="TEndpointDefinition"></typeparam>
    /// <param name="builder"></param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public static IServiceCollection AddEndpointDefinition<TEndpointDefinition>(this IServiceCollection services)
        where TEndpointDefinition : IEndpointDefinition
    {
        services.AddSingleton(typeof(IEndpointDefinition), typeof(TEndpointDefinition));
        return services;
    }

    /// <summary>
    /// Add endpoint definition
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="definitionType"></param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public static IServiceCollection AddEndpointDefinition(this IServiceCollection services, Type definitionType)
    {
        services.AddSingleton(typeof(IEndpointDefinition), definitionType);
        return services;
    }

    private static Type? FindGenericBaseType(Type currentType, Type genericBaseType)
    {
        Type? type = currentType;
        while (type != null)
        {
            var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
            if (genericType != null && genericType == genericBaseType)
            {
                return type;
            }
            type = type.BaseType;
        }
        return null;
    }
}
