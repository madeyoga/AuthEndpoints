using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;

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
    /// Skip CSRF only when the caller presented a non-empty <c>Authorization: Bearer</c>
    /// header and Identity bearer or JWT authenticated that request. An Identity application
    /// cookie always forces the check. A cross-site request cannot attach that header without
    /// a CORS preflight, so the header is the CSRF signal. Hosts that read the access token
    /// from a cookie still send the CSRF token; this filter does not call <c>OnMessageReceived</c>.
    /// </summary>
    private static async Task<bool> ShouldSkipAntiforgeryAsync(HttpContext httpContext)
    {
        if (await IsAuthenticatedAsync(httpContext, SignInSchemes.Application))
        {
            return false;
        }

        if (!HasBearerAuthorizationHeader(httpContext.Request))
        {
            return false;
        }

        foreach (var scheme in SignInSchemes.Bearer)
        {
            if (await IsAuthenticatedAsync(httpContext, scheme))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasBearerAuthorizationHeader(HttpRequest request)
    {
        var values = request.Headers.Authorization;
        if (StringValues.IsNullOrEmpty(values))
        {
            return false;
        }

        foreach (var value in values)
        {
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }

            const string prefix = "Bearer ";
            if (value.Length > prefix.Length
                && value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(value[prefix.Length..]))
            {
                return true;
            }
        }

        return false;
    }

    private static async Task<bool> IsAuthenticatedAsync(HttpContext httpContext, string scheme)
    {
        var schemeProvider = httpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
        if (await schemeProvider.GetSchemeAsync(scheme) is null)
        {
            return false;
        }

        var result = await httpContext.AuthenticateAsync(scheme);
        return result.Succeeded && result.Principal?.Identity?.IsAuthenticated == true;
    }
}
