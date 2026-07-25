using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class AntiforgeryRouteBuilderExtensions
{
    public static IEndpointConventionBuilder EnableAntiforgery(this RouteHandlerBuilder builder)
    {
        return builder.WithMetadata(AntiforgeryMetadata.ValidationRequired);
    }

    public static RouteGroupBuilder EnableAntiforgery(this RouteGroupBuilder builder)
    {
        return builder.WithMetadata(AntiforgeryMetadata.ValidationRequired);
    }

    public static RouteHandlerBuilder RequireAntiforgery(this RouteHandlerBuilder builder)
    {
        // Filter-only: do not attach ValidationRequired metadata, otherwise UseAntiforgery /
        // AntiforgeryEnforcementMiddleware reject before the bearer-skip logic in the filter runs.
        return builder.AddEndpointFilter<EnforceAntiforgeryEndpointFilters>();
    }

    public static RouteGroupBuilder RequireAntiforgery(this RouteGroupBuilder builder)
    {
        return builder.AddEndpointFilter<EnforceAntiforgeryEndpointFilters>();
    }
}

public class EnforceAntiforgeryEndpointFilters : IEndpointFilter
{
    private readonly IAntiforgery antiforgery;

    public EnforceAntiforgeryEndpointFilters(IAntiforgery antiforgery)
    {
        this.antiforgery = antiforgery;
    }

    public virtual async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        if (await ShouldSkipAntiforgeryAsync(context.HttpContext))
        {
            return await next(context);
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.BadRequest("Invalid or missing CSRF token.");
        }

        return await next(context);
    }

    /// <summary>
    /// Skip CSRF when the request is authenticated via bearer schemes (Identity bearer or JWT Bearer)
    /// and not via the application cookie. Cookie sessions still require antiforgery even if a
    /// ReAuth cookie is also present.
    /// </summary>
    private static async Task<bool> ShouldSkipAntiforgeryAsync(HttpContext httpContext)
    {
        if (await IsAuthenticatedAsync(httpContext, IdentityConstants.ApplicationScheme)
            || await IsAuthenticatedAsync(httpContext, IdentityConstants.ExternalScheme))
        {
            return false;
        }

        return await IsAuthenticatedAsync(httpContext, IdentityConstants.BearerScheme)
            || await IsAuthenticatedAsync(httpContext, JwtBearerDefaults.AuthenticationScheme);
    }

    private static async Task<bool> IsAuthenticatedAsync(HttpContext httpContext, string scheme)
    {
        var result = await httpContext.AuthenticateAsync(scheme);
        return result.Succeeded && result.Principal?.Identity?.IsAuthenticated == true;
    }
}
