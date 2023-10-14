using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

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

        services.AddIdentityCore<TUser>()
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
        return ConfigureServices<TUser, TContext>(services);
    }

    /// <summary>
    /// Add endpoint definition
    /// </summary>
    /// <typeparam name="TEndpointDefinition"></typeparam>
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
    /// <param name="definitionType"></param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public static IServiceCollection AddEndpointDefinition(this IServiceCollection services, Type definitionType)
    {
        services.AddSingleton(typeof(IEndpointDefinition), definitionType);
        return services;
    }
}
