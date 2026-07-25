using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.ReAuth;

public static class ReAuthApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps reauthentication endpoints onto the current route group
    /// (<c>/confirmIdentity</c>, <c>/confirmIdentity/passkeyOptions</c>, <c>/manage/authMethods</c>).
    /// </summary>
    public static IEndpointConventionBuilder MapReAuthEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        bool requireAntiforgery = false)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var group = endpoints.MapGroup("");
        var authorize = ManagementAuthorization.CreateAuthorizeAttribute(endpoints);

        var confirm = group.MapPost("/confirmIdentity", ReAuthEndpoints<TUser>.ConfirmIdentity)
            .WithSummary("Confirm the user's identity and issue short-lived reauthentication credentials.")
            .WithDescription("""
                Provide exactly one proof: Password, TwoFactorCode, TwoFactorRecoveryCode, or CredentialJson (passkey assertion).
                On success, issues a temporary AuthEndpoints.ReAuth cookie (5 minutes) and a reauthToken
                for the X-AuthEndpoints-Reauth header on sensitive API actions.
                """)
            .RequireAuthorization(authorize)
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityPolicy);

        var passkeyOptions = group.MapPost("/confirmIdentity/passkeyOptions", ReAuthEndpoints<TUser>.PasskeyOptions)
            .WithSummary("Generate WebAuthn request options for reauthentication with a passkey.")
            .WithDescription("Scoped to the currently signed-in user (no username query).")
            .RequireAuthorization(authorize)
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityPolicy);

        if (requireAntiforgery)
        {
            confirm.RequireAntiforgery();
            passkeyOptions.RequireAntiforgery();
        }

        var manage = group.MapGroup("/manage").RequireAuthorization(authorize);
        manage.MapGet("/authMethods", ReAuthEndpoints<TUser>.AuthMethods)
            .WithSummary("List available step-up / reauthentication methods for the current user.");

        return group;
    }
}
