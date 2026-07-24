using Microsoft.AspNetCore.Antiforgery;
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
        return builder.WithMetadata(AntiforgeryMetadata.ValidationRequired)
                      .AddEndpointFilter<EnforceAntiforgeryEndpointFilters>();
    }

    public static RouteGroupBuilder RequireAntiforgery(this RouteGroupBuilder builder)
    {
        return builder.WithMetadata(AntiforgeryMetadata.ValidationRequired)
                      .AddEndpointFilter<EnforceAntiforgeryEndpointFilters>();
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
        if (ShouldSkipAntiforgery(context.HttpContext))
        {
            return await next(context);
        }

        await antiforgery.ValidateRequestAsync(context.HttpContext);

        return await next(context);
    }

    /// <summary>
    /// Skip CSRF only when the request is authenticated exclusively via bearer schemes
    /// (Identity bearer or JWT Bearer). Cookie or anonymous requests still require antiforgery.
    /// </summary>
    private static bool ShouldSkipAntiforgery(HttpContext httpContext)
    {
        var hasCookieIdentity = false;
        var hasBearerIdentity = false;

        foreach (var identity in httpContext.User.Identities)
        {
            if (!identity.IsAuthenticated)
            {
                continue;
            }

            var scheme = identity.AuthenticationType;
            if (scheme == IdentityConstants.ApplicationScheme
                || scheme == IdentityConstants.ExternalScheme
                || scheme == AuthEndpointsConstants.ReAuthScheme)
            {
                hasCookieIdentity = true;
            }
            else if (scheme == IdentityConstants.BearerScheme
                || scheme == JwtBearerDefaults.AuthenticationScheme)
            {
                hasBearerIdentity = true;
            }
        }

        return hasBearerIdentity && !hasCookieIdentity;
    }
}
