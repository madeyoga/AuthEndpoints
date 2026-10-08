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
/// When the store supports security stamps, the proof's stamp must match the user's current stamp.
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

        var reauthPrincipal = await FindMatchingReauthAsync(httpContext, userIdClaimType, primaryUserId);
        if (reauthPrincipal is null)
        {
            return;
        }

        if (!await SecurityStampMatchesAsync(httpContext, context.User, reauthPrincipal))
        {
            return;
        }

        context.Succeed(requirement);
    }

    private async Task<bool> SecurityStampMatchesAsync(
        HttpContext httpContext,
        ClaimsPrincipal signedInUser,
        ClaimsPrincipal reauthPrincipal)
    {
        var stamps = httpContext.RequestServices.GetRequiredService<IReAuthSecurityStamp>();
        if (!stamps.SupportsUserSecurityStamp)
        {
            return true;
        }

        var stampClaimType = _identityOptions.Value.ClaimsIdentity.SecurityStampClaimType;
        var proofStamp = reauthPrincipal.FindFirst(stampClaimType)?.Value;
        if (string.IsNullOrEmpty(proofStamp))
        {
            return false;
        }

        var currentStamp = await stamps.GetCurrentStampAsync(signedInUser);
        return !string.IsNullOrEmpty(currentStamp)
            && string.Equals(proofStamp, currentStamp, StringComparison.Ordinal);
    }

    private static async Task<ClaimsPrincipal?> FindMatchingReauthAsync(
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
                return result.Principal;
            }
        }

        return null;
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
