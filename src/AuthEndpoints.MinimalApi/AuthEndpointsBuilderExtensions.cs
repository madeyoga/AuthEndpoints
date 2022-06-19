using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.MinimalApi;

public static class AuthEndpointsBuilderExtensions
{
    public static AuthEndpointsBuilder AddBasicAuthenticationEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(BasicAuthEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);
        return builder;
    }

    public static AuthEndpointsBuilder AddJwtEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(JwtEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);
        return builder;
    }

    public static AuthEndpointsBuilder Add2FAEndpoints(this AuthEndpointsBuilder builder)
    {
        var type = typeof(TwoFactorEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        builder.Services.AddSingleton(typeof(IEndpointDefinition), type);
        return builder;
    }

    public static AuthEndpointsBuilder AddEndpointDefinition<TEndpointDefinition>(this AuthEndpointsBuilder builder)
        where TEndpointDefinition : IEndpointDefinition
    {
        builder.Services.AddSingleton(typeof(IEndpointDefinition), typeof(TEndpointDefinition));
        return builder;
    }

    public static AuthEndpointsBuilder AddEndpointDefinition(this AuthEndpointsBuilder builder, Type definitionType)
    {
        builder.Services.AddSingleton(typeof(IEndpointDefinition), definitionType);
        return builder;
    }

    public static AuthEndpointsBuilder AddAllEndpointDefinitions(this AuthEndpointsBuilder builder)
    {
        AddBasicAuthenticationEndpoints(builder);
        AddJwtEndpoints(builder);
        Add2FAEndpoints(builder);
        return builder;
    }
}
