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
            o.AddScheme("TokenBearer", scheme =>
            {
                scheme.HandlerType = typeof(TokenBearerHandler<,,>).MakeGenericType(keyType, userType, contextType);
                scheme.DisplayName = "";
            });
        });
        //if (configureOptions != null)
        //{
        //    services.Configure(authenticationScheme, configureOptions);
        //}
        builder.Services.AddOptions<TokenBearerOptions>("TokenBearer").Validate(o =>
        {
            o.Validate("TokenBearer");
            return true;
        });
        builder.Services.AddTransient(typeof(TokenBearerHandler<,,>).MakeGenericType(keyType, userType, contextType));

        return builder;
    }

    public static AuthenticationBuilder AddTokenBearer<TKey, TUser, TContext>(this AuthenticationBuilder builder)
    {
        return AddTokenBearer(builder, typeof(TKey), typeof(TUser), typeof(TContext));
    }

}
