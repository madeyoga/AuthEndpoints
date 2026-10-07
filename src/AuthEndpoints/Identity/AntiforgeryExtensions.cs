using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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
    /// Skip CSRF only when the caller presented <c>Authorization: Bearer</c> and a bearer
    /// scheme authenticated that request. An Identity application or external cookie still
    /// forces the check. A token supplied from a cookie (the usual <c>OnMessageReceived</c>
    /// pattern) also forces the check, including when the header is present as well,
    /// because the browser attaches that cookie on its own.
    /// </summary>
    private static async Task<bool> ShouldSkipAntiforgeryAsync(HttpContext httpContext)
    {
        if (await IsAuthenticatedAsync(httpContext, IdentityConstants.ApplicationScheme)
            || await IsAuthenticatedAsync(httpContext, IdentityConstants.ExternalScheme))
        {
            return false;
        }

        if (httpContext.Request.Cookies.Count > 0
            && (await NonHeaderSourceSuppliesTokenAsync(httpContext, IdentityConstants.BearerScheme)
                || await NonHeaderSourceSuppliesTokenAsync(httpContext, JwtBearerDefaults.AuthenticationScheme)))
        {
            return false;
        }

        if (!HasBearerAuthorizationHeader(httpContext.Request))
        {
            return false;
        }

        return await IsAuthenticatedAsync(httpContext, IdentityConstants.BearerScheme)
            || await IsAuthenticatedAsync(httpContext, JwtBearerDefaults.AuthenticationScheme);
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

    /// <summary>
    /// True when bearer or JWT <c>OnMessageReceived</c> supplies a token after the
    /// Authorization header is removed. That is how hosts read the access token from a cookie.
    /// The header is restored before the method returns. A throw from the host event does not
    /// count as a supplied token; the later scheme authentication still has to succeed.
    /// </summary>
    private static async Task<bool> NonHeaderSourceSuppliesTokenAsync(HttpContext httpContext, string schemeName)
    {
        var schemeProvider = httpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
        var scheme = await schemeProvider.GetSchemeAsync(schemeName);
        if (scheme is null)
        {
            return false;
        }

        var authorization = httpContext.Request.Headers.Authorization;
        httpContext.Request.Headers.Remove("Authorization");
        try
        {
            if (string.Equals(schemeName, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal))
            {
                var monitor = httpContext.RequestServices.GetService<IOptionsMonitor<JwtBearerOptions>>();
                var options = monitor?.Get(scheme.Name);
                if (options?.Events is not { } events)
                {
                    return false;
                }

                var context = new Microsoft.AspNetCore.Authentication.JwtBearer.MessageReceivedContext(
                    httpContext,
                    scheme,
                    options);
                await events.MessageReceived(context);
                return TokenWasSupplied(context.Token, context.Result);
            }

            if (string.Equals(schemeName, IdentityConstants.BearerScheme, StringComparison.Ordinal))
            {
                var monitor = httpContext.RequestServices.GetService<IOptionsMonitor<BearerTokenOptions>>();
                var options = monitor?.Get(scheme.Name);
                if (options?.Events is not { } events)
                {
                    return false;
                }

                var context = new Microsoft.AspNetCore.Authentication.BearerToken.MessageReceivedContext(
                    httpContext,
                    scheme,
                    options);
                await events.MessageReceivedAsync(context);
                return TokenWasSupplied(context.Token, context.Result);
            }

            return false;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (StringValues.IsNullOrEmpty(authorization))
            {
                httpContext.Request.Headers.Remove("Authorization");
            }
            else
            {
                httpContext.Request.Headers.Authorization = authorization;
            }
        }
    }

    private static bool TokenWasSupplied(string? token, AuthenticateResult? result) =>
        !string.IsNullOrWhiteSpace(token) || result?.Succeeded == true;

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
