using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Requires a ReAuth cookie or bearer proof. This is not <c>RequireReauth()</c>:
/// that policy replaces <see cref="HttpContext.User"/> with the ReAuth principal,
/// and the shared antiforgery filter then rejects the application user's CSRF token.
/// </summary>
internal sealed class ExternalReauthFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (!await HasReauthAsync(context.HttpContext))
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }

    private static async Task<bool> HasReauthAsync(HttpContext httpContext)
    {
        if (await HasClaimAsync(httpContext, AuthEndpointsConstants.ReAuthScheme))
        {
            return true;
        }

        return await HasClaimAsync(httpContext, AuthEndpointsConstants.ReAuthBearerScheme);
    }

    private static async Task<bool> HasClaimAsync(HttpContext httpContext, string scheme)
    {
        var result = await httpContext.AuthenticateAsync(scheme);
        return result.Succeeded
            && result.Principal?.HasClaim("Reauth", "true") == true;
    }
}
