using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

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
    /// Requires a CSRF token unless the request authenticated with a scheme in
    /// <see cref="AuthEndpointsAntiforgeryOptions.BearerSchemes"/> (default: Identity bearer and JWT)
    /// using a non-empty <c>Authorization: Bearer</c> header. An application-cookie sign-in
    /// still requires the token. A JWT read from a cookie in <c>OnMessageReceived</c> is not that header.
    /// </summary>
    public static RouteHandlerBuilder RequireAntiforgery(this RouteHandlerBuilder builder)
    {
        return builder.RequireAntiforgery(allowBearer: true);
    }

    /// <summary>
    /// Requires a CSRF token. When <paramref name="allowBearer"/> is <see langword="true"/>, this is
    /// <see cref="RequireAntiforgery(RouteHandlerBuilder)"/>. When it is <see langword="false"/>, every
    /// caller needs the token, including one that authenticated with an <c>Authorization: Bearer</c>
    /// header and a scheme in <see cref="AuthEndpointsAntiforgeryOptions.BearerSchemes"/>. Use
    /// <see langword="false"/> for routes a token must never call on its own, such as consent approval
    /// or account deletion.
    /// </summary>
    /// <remarks>
    /// When a group and a route both require antiforgery, both filters run, so the stricter one wins.
    /// </remarks>
    public static RouteHandlerBuilder RequireAntiforgery(this RouteHandlerBuilder builder, bool allowBearer)
    {
        // Filter-only for the framework metadata: do not attach ValidationRequired, otherwise
        // UseAntiforgery rejects before the bearer-skip logic in the filter runs.
        builder.WithMetadata(AuthEndpointsAntiforgeryMetadata.Instance);
        return allowBearer
            ? builder.AddEndpointFilter<EnforceAntiforgeryEndpointFilters>()
            : builder.AddEndpointFilter<TokenAlwaysRequiredAntiforgeryEndpointFilter>();
    }

    /// <inheritdoc cref="RequireAntiforgery(RouteHandlerBuilder)"/>
    public static RouteGroupBuilder RequireAntiforgery(this RouteGroupBuilder builder)
    {
        return builder.RequireAntiforgery(allowBearer: true);
    }

    /// <inheritdoc cref="RequireAntiforgery(RouteHandlerBuilder, bool)"/>
    public static RouteGroupBuilder RequireAntiforgery(this RouteGroupBuilder builder, bool allowBearer)
    {
        builder.WithMetadata(AuthEndpointsAntiforgeryMetadata.Instance);
        return allowBearer
            ? builder.AddEndpointFilter<EnforceAntiforgeryEndpointFilters>()
            : builder.AddEndpointFilter<TokenAlwaysRequiredAntiforgeryEndpointFilter>();
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
        if (await BearerRequest.IsHeaderBearerOnlyAsync(context.HttpContext))
        {
            return await next(context);
        }

        return await AntiforgeryValidation.ValidateAsync(antiforgery, context, next);
    }
}

internal sealed class TokenAlwaysRequiredAntiforgeryEndpointFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        return AntiforgeryValidation.ValidateAsync(antiforgery, context, next);
    }
}

internal static class AntiforgeryValidation
{
    public static async ValueTask<object?> ValidateAsync(
        IAntiforgery antiforgery,
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
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
}

/// <summary>
/// Shared rule for the CSRF skip in <see cref="EnforceAntiforgeryEndpointFilters"/> and the ReAuth
/// cookie decision on <c>POST /confirmIdentity</c>.
/// </summary>
internal static class BearerRequest
{
    /// <summary>
    /// True when the application cookie did not authenticate the request, the request has a non-empty
    /// <c>Authorization: Bearer</c> header, and a non-cookie scheme in
    /// <see cref="AuthEndpointsAntiforgeryOptions.BearerSchemes"/> authenticates it.
    /// A cross-site request cannot set <c>Authorization</c> without a CORS preflight.
    /// </summary>
    public static async Task<bool> IsHeaderBearerOnlyAsync(HttpContext httpContext)
    {
        if (await SignInSchemes.IsAuthenticatedAsync(httpContext, SignInSchemes.Application))
        {
            return false;
        }

        if (!SignInSchemes.HasBearerAuthorizationHeader(httpContext.Request))
        {
            return false;
        }

        var services = httpContext.RequestServices;
        var options = services.GetService<IOptions<AuthEndpointsAntiforgeryOptions>>()?.Value
            ?? new AuthEndpointsAntiforgeryOptions();
        var schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();

        foreach (var name in options.BearerSchemes)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var scheme = await schemeProvider.GetSchemeAsync(name);
            if (scheme is null || IsCookieHandler(scheme.HandlerType))
            {
                // A cookie is sent on a cross-site request, so a cookie scheme never skips the check.
                continue;
            }

            var result = await httpContext.AuthenticateAsync(name);
            if (result.Succeeded && result.Principal?.Identity?.IsAuthenticated == true)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsCookieHandler(Type handlerType) =>
        typeof(CookieAuthenticationHandler).IsAssignableFrom(handlerType);
}
