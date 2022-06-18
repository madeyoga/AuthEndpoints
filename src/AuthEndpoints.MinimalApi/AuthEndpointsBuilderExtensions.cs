using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.MinimalApi;

public static class AuthEndpointsBuilderExtensions
{
    public static AuthEndpointsBuilder AddBasicAuthenticationEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(BasicAuthEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.TryAddSingleton(type);
        return builder;
    }

    public static AuthEndpointsBuilder AddJwtEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(JwtEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.TryAddSingleton(type);
        return builder;
    }

    public static AuthEndpointsBuilder Add2FAEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(TwoFactorEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.TryAddSingleton(type);
        return builder;
    }

    public static AuthEndpointsBuilder AddAllEndpointDefinitions( this AuthEndpointsBuilder builder)
    {
        AddBasicAuthenticationEndpoints(builder);
        AddJwtEndpoints(builder);
        Add2FAEndpoints(builder);
        return builder;
    }
}
