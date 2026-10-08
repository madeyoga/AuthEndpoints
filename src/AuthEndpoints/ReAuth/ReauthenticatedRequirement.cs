using System.Security.Claims;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.ReAuth;

/// <summary>
/// Requires a signed-in user and a ReAuth proof for that same user.
/// The proof is authenticated here and is never copied onto <see cref="HttpContext.User"/>.
/// </summary>
internal sealed class ReauthenticatedRequirement : IAuthorizationRequirement;

internal sealed class ReauthenticatedHandler : AuthorizationHandler<ReauthenticatedRequirement>
{
    private static readonly string[] ReAuthSchemes =
    [
        AuthEndpointsConstants.ReAuthScheme,
        AuthEndpointsConstants.ReAuthBearerScheme,
    ];

    private readonly IOptions<IdentityOptions> _identityOptions;

    public ReauthenticatedHandler(IOptions<IdentityOptions> identityOptions)
    {
        _identityOptions = identityOptions;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ReauthenticatedRequirement requirement)
    {
        if (context.Resource is not HttpContext httpContext)
        {
            return;
        }

        if (!IsPrimaryPrincipal(context.User))
        {
            return;
        }

        var userIdClaimType = _identityOptions.Value.ClaimsIdentity.UserIdClaimType;
        var primaryUserId = context.User.FindFirst(userIdClaimType)?.Value;
        if (string.IsNullOrEmpty(primaryUserId))
        {
            return;
        }

        if (await HasMatchingReauthAsync(httpContext, userIdClaimType, primaryUserId))
        {
            context.Succeed(requirement);
        }
    }

    private static async Task<bool> HasMatchingReauthAsync(
        HttpContext httpContext,
        string userIdClaimType,
        string primaryUserId)
    {
        var schemeProvider = httpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
        foreach (var scheme in ReAuthSchemes)
        {
            if (await schemeProvider.GetSchemeAsync(scheme) is null)
            {
                continue;
            }

            var result = await httpContext.AuthenticateAsync(scheme);
            if (result.Succeeded && IsMatchingReauth(result.Principal, userIdClaimType, primaryUserId))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsMatchingReauth(ClaimsPrincipal? principal, string userIdClaimType, string primaryUserId)
    {
        if (principal?.HasClaim("Reauth", "true") != true)
        {
            return false;
        }

        var reauthUserId = principal.FindFirst(userIdClaimType)?.Value;
        return !string.IsNullOrEmpty(reauthUserId)
            && string.Equals(reauthUserId, primaryUserId, StringComparison.Ordinal);
    }

    private static bool IsPrimaryPrincipal(ClaimsPrincipal? principal)
    {
        if (principal is null)
        {
            return false;
        }

        foreach (var identity in principal.Identities)
        {
            if (!identity.IsAuthenticated)
            {
                continue;
            }

            if (SignInSchemes.IsPrimaryIdentity(identity))
            {
                return true;
            }
        }

        return false;
    }
}
