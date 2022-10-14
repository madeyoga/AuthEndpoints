using AuthEndpoints.Core;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.Session;

public static class ServiceCollectionExtensions
{
    private static void AddSessionCore<TUser>(IServiceCollection services)
        where TUser : class
    {
        services.TryAddScoped<SecurityCookieAuthenticationEvents<TUser>>();

        services.AddHttpContextAccessor();

        Type userType = typeof(TUser);
        Type keyType = TypeHelper.FindKeyType(userType)!;
        Type endpointsType = typeof(Endpoints<,>).MakeGenericType(keyType, userType);
        services.AddEndpointDefinition(endpointsType);
    }

    public static IServiceCollection AddSessionEndpoints<TUser>(this IServiceCollection services)
        where TUser : class
    {
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.Cookie.Domain = "localhost";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Only allow cookies in HTTPS contexts (if not in the development environment)

            // This is the most important part here (which I missed the other times I tried to use cookies in SPAs)
            options.EventsType = typeof(SecurityCookieAuthenticationEvents<TUser>);
        });

        AddSessionCore<TUser>(services);

        return services;
    }

    public static IServiceCollection AddSessionEndpoints<TUser>(this IServiceCollection services, Action<CookieAuthenticationOptions> setup)
        where TUser : class
    {
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, setup);

        AddSessionCore<TUser>(services);

        return services;
    }
}
