using AuthEndpoints.Core;
using AuthEndpoints.Core.Endpoints;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.MinimalApi;

/// <summary>
/// Provides extensions to easily add authentication endpoints using the minimal api.
/// </summary>
public static class AuthEndpointsBuilderExtensions
{
    public static AuthEndpointsBuilder AddBasicAuthenticationEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(BasicAuthEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);
        return builder;
    }

    public static AuthEndpointsBuilder Add2FAEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(TwoFactorEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);
        return builder;
    }
}
