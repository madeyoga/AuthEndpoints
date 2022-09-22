using AuthEndpoints.Core;
using AuthEndpoints.Core.Endpoints;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.MinimalApi;

/// <summary>
/// Provides extensions to easily add users api endpoints.
/// </summary>
public static class AuthEndpointsBuilderExtensions
{
    [Obsolete("Please use AddUsersApiEndpoints instead.")]
    public static AuthEndpointsBuilder AddBasicAuthenticationEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(UsersEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);
        return builder;
    }

    /// <summary>
    /// Add APIs for creating, retrieving, updating, and deleting users.
    /// </summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static AuthEndpointsBuilder AddUsersApiEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(UsersEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);
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
        return builder;
    }
}
