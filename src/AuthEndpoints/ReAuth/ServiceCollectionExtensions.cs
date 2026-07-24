using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.ReAuth;

internal sealed class ReAuthSchemeMarker;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the short-lived ReAuth cookie scheme and authorization policy.
    /// </summary>
    public static IServiceCollection AddReAuthScheme(this IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(ReAuthSchemeMarker)))
        {
            return services;
        }

        services.AddSingleton<ReAuthSchemeMarker>();

        services.AddAuthentication()
            .AddCookie(AuthEndpointsConstants.ReAuthScheme, options =>
            {
                options.Cookie.Name = AuthEndpointsConstants.ReAuthScheme;
                options.Cookie.HttpOnly = true;
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
            });

        services.AddAuthorizationBuilder()
            .AddPolicy("ReAuthPolicy", policy =>
            {
                policy.AddAuthenticationSchemes(AuthEndpointsConstants.ReAuthScheme);
                policy.RequireAuthenticatedUser();
            });

        return services;
    }

    public static TBuilder RequireReauth<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        return builder.RequireAuthorization("ReAuthPolicy");
    }
}
