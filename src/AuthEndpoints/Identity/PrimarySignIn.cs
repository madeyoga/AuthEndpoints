using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

/// <summary>
/// Requires a primary sign-in scheme (application cookie, Identity bearer, or JWT bearer).
/// A ReAuth cookie or <c>X-AuthEndpoints-Reauth</c> token is not a sign-in. Combined
/// authorization policies merge those principals, so this filter rejects a request that
/// only the ReAuth schemes authenticated.
/// </summary>
internal static class PrimarySignIn
{
    private static readonly string[] Schemes =
    [
        IdentityConstants.ApplicationScheme,
        IdentityConstants.BearerScheme,
        JwtBearerDefaults.AuthenticationScheme
    ];

    public static async Task<bool> IsAuthenticatedAsync(HttpContext httpContext)
    {
        var schemeProvider = httpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
        foreach (var scheme in Schemes)
        {
            if (await schemeProvider.GetSchemeAsync(scheme) is null)
            {
                continue;
            }

            var result = await httpContext.AuthenticateAsync(scheme);
            if (result.Succeeded && result.Principal?.Identity?.IsAuthenticated == true)
            {
                return true;
            }
        }

        return false;
    }

    public static TBuilder RequirePrimarySignIn<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        return builder.AddEndpointFilter(static async (context, next) =>
        {
            if (!await IsAuthenticatedAsync(context.HttpContext))
            {
                return Results.Unauthorized();
            }

            return await next(context);
        });
    }
}
