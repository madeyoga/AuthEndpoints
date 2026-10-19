using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

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

    /// <summary>
    /// Requires a CSRF token unless the request authenticated with Identity bearer or JWT
    /// using a non-empty <c>Authorization: Bearer</c> header. An application-cookie sign-in
    /// still requires the token. A JWT read from a cookie in <c>OnMessageReceived</c> is not that header.
    /// </summary>
    public static RouteHandlerBuilder RequireAntiforgery(this RouteHandlerBuilder builder)
    {
        // Filter-only for the framework metadata: do not attach ValidationRequired, otherwise
        // UseAntiforgery rejects before the bearer-skip logic in the filter runs.
        return builder
            .WithMetadata(AuthEndpointsAntiforgeryMetadata.Instance)
            .AddEndpointFilter<EnforceAntiforgeryEndpointFilters>();
    }

    /// <inheritdoc cref="RequireAntiforgery(RouteHandlerBuilder)"/>
    public static RouteGroupBuilder RequireAntiforgery(this RouteGroupBuilder builder)
    {
        return builder
            .WithMetadata(AuthEndpointsAntiforgeryMetadata.Instance)
            .AddEndpointFilter<EnforceAntiforgeryEndpointFilters>();
    }
}

// Not IAntiforgeryMetadata: UseAntiforgery validates before the endpoint filter can skip bearer calls.
internal sealed class AuthEndpointsAntiforgeryMetadata
{
    public static readonly AuthEndpointsAntiforgeryMetadata Instance = new();

    private AuthEndpointsAntiforgeryMetadata()
    {
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

    // A cross-site request cannot set Authorization without a CORS preflight.
    private static async Task<bool> ShouldSkipAntiforgeryAsync(HttpContext httpContext)
    {
        if (await SignInSchemes.IsAuthenticatedAsync(httpContext, SignInSchemes.Application))
        {
            return false;
        }

        if (!SignInSchemes.HasBearerAuthorizationHeader(httpContext.Request))
        {
            return false;
        }

        foreach (var scheme in SignInSchemes.Bearer)
        {
            if (await SignInSchemes.IsAuthenticatedAsync(httpContext, scheme))
            {
                return true;
            }
        }

        return false;
    }
}
