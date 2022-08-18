using AuthEndpoints.Core;
using AuthEndpoints.Core.Services;
using AuthEndpoints.TokenAuth.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.TokenAuth;

public static class TokenAuthServiceCollectionExtensions
{
    public static TokenAuthBuilder AddTokenAuthCore< TUser, TContext>(this IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        var identityUserType = TypeHelper.FindGenericBaseType(typeof(TUser), typeof(IdentityUser<>));
        if (identityUserType == null)
        {
            throw new InvalidOperationException("Generic type TUser is not IdentityUser");
        }
        var keyType = identityUserType.GenericTypeArguments[0];
        var userType = typeof(TUser);
        var contextType = typeof(TContext);

        services.AddScoped(typeof(AuthTokenValidator<,,>).MakeGenericType(keyType, userType, contextType));
        services.AddScoped<AuthTokenGenerator>();
        services.AddScoped(typeof(TokenRepository<,,>).MakeGenericType(keyType, userType, contextType));

        return new TokenAuthBuilder(keyType, userType, contextType, services);
    }

    public static TokenAuthBuilder AddTokenAuthEndpoints<TUser, TContext>(this IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        var builder = AddTokenAuthCore<TUser, TContext>(services);

        // Add auth scheme
        services.AddAuthentication("TokenBearer")
            .AddTokenBearer(builder.KeyType, builder.UserType, builder.ContextType);

        var loginServiceType = typeof(TokenAuthLoginService<,,>).MakeGenericType(builder.KeyType, builder.UserType, builder.ContextType);
        services.AddScoped(typeof(ILoginService<TUser>), loginServiceType);

        var endpointsType = typeof(TokenAuthEndpoints<,,>).MakeGenericType(builder.KeyType, builder.UserType, builder.ContextType);
        services.AddEndpointDefinition(endpointsType);

        return builder;
    }
}
