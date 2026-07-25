using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.ReAuth;

internal sealed class ReAuthSchemeMarker;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the short-lived ReAuth cookie scheme, bearer step-up token scheme, and authorization policy.
    /// </summary>
    public static IServiceCollection AddReAuthScheme(this IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(ReAuthSchemeMarker)))
        {
            return services;
        }

        services.AddSingleton<ReAuthSchemeMarker>();
        services.TryAddSingleton(TimeProvider.System);
        services.AddDataProtection();
        services.TryAddSingleton<ReAuthTokenService>();

        services.AddAuthentication()
            .AddCookie(AuthEndpointsConstants.ReAuthScheme, options =>
            {
                options.Cookie.Name = AuthEndpointsConstants.ReAuthScheme;
                options.Cookie.HttpOnly = true;
                // SameAsRequest → Secure on HTTPS (production); allows HTTP test hosts.
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.SlidingExpiration = false;

                options.Events.OnRedirectToLogin = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };

                options.Events.OnRedirectToAccessDenied = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };

                options.Events.OnRedirectToLogout = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status204NoContent;
                    return Task.CompletedTask;
                };
            })
            .AddScheme<AuthenticationSchemeOptions, ReAuthBearerAuthenticationHandler>(
                AuthEndpointsConstants.ReAuthBearerScheme,
                _ => { });

        services.AddAuthorizationBuilder()
            .AddPolicy("ReAuthPolicy", policy =>
            {
                policy.AddAuthenticationSchemes(
                    AuthEndpointsConstants.ReAuthScheme,
                    AuthEndpointsConstants.ReAuthBearerScheme);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("Reauth", "true");
            });

        return services;
    }

    public static TBuilder RequireReauth<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        return builder.RequireAuthorization("ReAuthPolicy");
    }
}
