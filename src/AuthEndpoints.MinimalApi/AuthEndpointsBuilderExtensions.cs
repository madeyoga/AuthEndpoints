using AuthEndpoints.MinimalApi.EndpointDefinitions;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.MinimalApi;

public static class AuthEndpointsBuilderExtensions
{
    public static AuthEndpointsBuilder AddBasicAuthenticationEndpoints<TKey, TUser>(this AuthEndpointsBuilder builder)
    {
        var type = typeof(BasicAuthEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(type);
        return builder;
    }

    public static AuthEndpointsBuilder AddJwtEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(JwtEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(type);
        return builder;
    }

    public static AuthEndpointsBuilder Add2FAEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(TwoFactorEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(type);
        return builder;
    }
}
