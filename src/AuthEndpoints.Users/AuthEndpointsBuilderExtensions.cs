using AuthEndpoints.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.Users;

/// <summary>
/// Provides extensions to easily add users api endpoints.
/// </summary>
public static class AuthEndpointsBuilderExtensions
{
    /// <summary>
    /// Add APIs for creating, retrieving, updating, and deleting users.
    /// </summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static AuthEndpointsBuilder AddUsersApiEndpoints(this AuthEndpointsBuilder builder)
    {
        return AddUsersApiEndpoints(builder, o => { });
    }

    /// <summary>
    /// Add APIs for creating, retrieving, updating, and deleting users.
    /// </summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static AuthEndpointsBuilder AddUsersApiEndpoints(this AuthEndpointsBuilder builder, Action<UserEndpointsOptions> setup)
    {
        if (setup != null)
        {
            builder.Services.AddOptions<UserEndpointsOptions>()
                .Configure(setup);
        }

        var type = typeof(UsersEndpointDefinition<>).MakeGenericType(builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);

        builder.Services.TryAddSingleton(typeof(IEmailSender<>).MakeGenericType(builder.UserType), typeof(DefaultEmailSender<>).MakeGenericType(builder.UserType));
        builder.Services.TryAddSingleton<IEmailSender, DefaultEmailSender>();

        return builder;
    }

    /// <summary>
    /// Add APIs for enabling user's Two Factor Authentication (via Email).
    /// </summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static AuthEndpointsBuilder Add2FAEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(TwoFactorEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);
        builder.Services.TryAddSingleton<IEmailSender, DefaultEmailSender>();

        return builder;
    }

    /// <summary>
    /// Adds an <see cref="IEmailSender"/>
    /// </summary>
    /// <typeparam name="TSender"></typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public static AuthEndpointsBuilder AddEmailSender<TSender>(this AuthEndpointsBuilder builder) where TSender : IEmailSender
    {
        builder.Services.AddSingleton(typeof(IEmailSender), typeof(TSender));
        return builder;
    }
}

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add APIs for creating, retrieving, updating, and deleting users.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static AuthEndpointsBuilder AddUsersApiEndpoints<TUser, TContext>(this IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        return AddUsersApiEndpoints<TUser, TContext>(services, o => { });
    }

    /// <summary>
    /// Add APIs for creating, retrieving, updating, and deleting users.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="setup"></param>
    /// <returns></returns>
    public static AuthEndpointsBuilder AddUsersApiEndpoints<TUser, TContext>(this IServiceCollection services, Action<UserEndpointsOptions> setup)
        where TUser : class
        where TContext : DbContext
    {
        if (setup != null)
        {
            services.AddOptions<UserEndpointsOptions>()
                .Configure(setup);
        }

        var builder = services.AddAuthEndpointsCore<TUser, TContext>();

        var type = typeof(UsersEndpointDefinition<>).MakeGenericType(builder.UserType);
        services.AddSingleton(typeof(IEndpointDefinition), type);

        services.TryAddSingleton<IEmailSender<TUser>, DefaultEmailSender<TUser>>();
        services.TryAddSingleton<IEmailSender, DefaultEmailSender>();

        return builder;
    }
}
