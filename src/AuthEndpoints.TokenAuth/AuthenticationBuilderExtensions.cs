using AuthEndpoints.Core;
using AuthEndpoints.TokenAuth.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.TokenAuth;

public static class AuthenticationBuilderExtensions
{
    public static AuthenticationBuilder AddTokenBearer(this AuthenticationBuilder builder, Type keyType, Type userType, Type contextType)
    {
        builder.Services.Configure<AuthenticationOptions>(o =>
        {
            o.AddScheme(TokenBearerDefaults.AuthenticationScheme, scheme =>
            {
                scheme.HandlerType = typeof(TokenBearerHandler<,,>).MakeGenericType(keyType, userType, contextType);
                scheme.DisplayName = "Token Bearer Authentication";
            });
        });
        builder.Services.AddOptions<TokenBearerAuthenticationOptions>(TokenBearerDefaults.AuthenticationScheme).Validate(o =>
        {
            o.Validate(TokenBearerDefaults.AuthenticationScheme);
            return true;
        });
        builder.Services.AddTransient(typeof(TokenBearerHandler<,,>).MakeGenericType(keyType, userType, contextType));

        return builder;
    }

    public static AuthenticationBuilder AddTokenBearer(this AuthenticationBuilder builder, Type userType, Type contextType)
    {
        var keyType = TypeHelper.FindKeyType(userType)!;
        return AddTokenBearer(builder, keyType, userType, contextType);
    }

    public static AuthenticationBuilder AddTokenBearer<TUser, TContext>(this AuthenticationBuilder builder)
    {
        return AddTokenBearer(builder, typeof(TUser), typeof(TContext));
    }

    public static AuthenticationBuilder AddTokenBearer<Tkey, TUser, TContext>(this AuthenticationBuilder builder)
    {
        return AddTokenBearer(builder, typeof(Tkey), typeof(TUser), typeof(TContext));
    }
}
