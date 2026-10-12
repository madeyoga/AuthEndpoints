using System.Security.Claims;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

internal static class IdentityEndpointRoutes
{
    public static void MapRegister<TUser>(IEndpointRouteBuilder endpoints, string confirmEmailEndpointName)
        where TUser : class, new()
    {
        endpoints.MapPost("/register", (
            RegisterRequest registration,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.Register(registration, context, sp, confirmEmailEndpointName))
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy);
    }

    public static void MapPasswordLogin<TUser>(IEndpointRouteBuilder endpoints, PasswordLoginMode login)
        where TUser : class, new()
    {
        switch (login)
        {
            case PasswordLoginMode.None:
                return;
            case PasswordLoginMode.Cookie:
                endpoints.MapPost("/login", IdentityApiEndpoints<TUser>.LoginCookie)
                    .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);
                return;
            case PasswordLoginMode.IdentityBearer:
                endpoints.MapPost("/login", IdentityApiEndpoints<TUser>.Login)
                    .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);
                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(login), login, "Unknown password login mode.");
        }
    }

    public static void MapForgotPassword<TUser>(IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        endpoints.MapPost("/forgotPassword", IdentityApiEndpoints<TUser>.ForgotPassword)
            .WithSummary("Sends a password reset email to the user.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy);
    }

    public static void MapResetPassword<TUser>(IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        endpoints.MapPost("/resetPassword", IdentityApiEndpoints<TUser>.ResetPassword)
            .WithSummary("Resets the user's password using the provided token.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy);
    }

    public static RouteGroupBuilder MapConfirmEmail<TUser>(IEndpointRouteBuilder endpoints, string confirmEmailEndpointName)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            .WithName(confirmEmailEndpointName);

        routeGroup.MapPost("/resendConfirmationEmail", (
            ResendConfirmationEmailRequest resendRequest,
            ClaimsPrincipal claimsPrincipal,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.ResendConfirmationEmail(
                resendRequest,
                claimsPrincipal,
                context,
                sp,
                confirmEmailEndpointName))
            .WithSummary("Resends the confirmation email for the signed-in account.")
            .RequireAuthEndpointsUser()
            .RequireAntiforgery()
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy);

        return routeGroup;
    }

    public static void MapConfirmIdentity<TUser>(IEndpointRouteBuilder endpoints, bool requireAntiforgery)
        where TUser : class, new()
    {
        var confirm = endpoints.MapPost("/confirmIdentity", ReAuthEndpoints<TUser>.ConfirmIdentity)
            .WithSummary("Confirm the user's identity and issue short-lived reauthentication credentials.")
            .WithDescription("""
                Provide exactly one proof: Password, TwoFactorCode, TwoFactorRecoveryCode, or CredentialJson (passkey assertion).
                On success, returns reauthToken for the X-AuthEndpoints-Reauth header.
                Cookie sign-ins also receive a temporary AuthEndpoints.ReAuth cookie.
                A caller authenticated with Authorization: Bearer receives the token only.
                Both carry the user's security stamp and share ReAuth.Lifetime (default 5 minutes).
                """)
            .RequireAuthEndpointsUser()
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityPolicy);

        if (requireAntiforgery)
        {
            confirm.RequireAntiforgery();
        }
    }

    public static void MapPasskeyOptions<TUser>(IEndpointRouteBuilder endpoints, bool requireAntiforgery)
        where TUser : class, new()
    {
        var passkeyOptions = endpoints.MapPost("/confirmIdentity/passkeyOptions", ReAuthEndpoints<TUser>.PasskeyOptions)
            .WithSummary("Generate WebAuthn request options for reauthentication with a passkey.")
            .WithDescription("Scoped to the currently signed-in user (no username query).")
            .RequireAuthEndpointsUser()
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityPolicy);

        if (requireAntiforgery)
        {
            passkeyOptions.RequireAntiforgery();
        }
    }

    public static void MapAuthMethods<TUser>(IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var manage = endpoints.MapGroup("/manage").RequireAuthEndpointsUser();
        manage.MapGet("/authMethods", ReAuthEndpoints<TUser>.AuthMethods)
            .WithSummary("List available step-up / reauthentication methods for the current user.");
    }

    public static void MapManageInfoAndTwoFactor<TUser>(IEndpointRouteBuilder endpoints, string confirmEmailEndpointName)
        where TUser : class, new()
    {
        var accountGroup = endpoints.MapGroup("/manage").RequireAuthEndpointsUser();

        accountGroup.MapGet("/2fa", IdentityApiEndpoints<TUser>.TwoFactorStatus)
            .WithSummary("Get two-factor authentication status.");
        accountGroup.MapPost("/2fa", IdentityApiEndpoints<TUser>.ManageTwoFactor)
            .WithSummary("Enables or disables two-factor authentication.")
            .RequireAntiforgery()
            .RequireReauth();
        accountGroup.MapGet("/info", IdentityApiEndpoints<TUser>.ManageInfoGet);
        accountGroup.MapPost("/info", (
            ClaimsPrincipal claimsPrincipal,
            InfoRequest infoRequest,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.ManageInfoPost(
                claimsPrincipal,
                infoRequest,
                context,
                sp,
                confirmEmailEndpointName))
            .WithSummary("Updates the current user account information.")
            .RequireAntiforgery()
            .RequireReauth();
    }

    public static void MapCookieSession<TUser>(IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        endpoints.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization()
            .RequireAntiforgery();

        endpoints.MapGet("/csrfToken", IdentityApiEndpoints<TUser>.GetAntiforgeryToken);
    }

    public static void MapBearerSession<TUser>(IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        endpoints.MapPost("/refresh", IdentityApiEndpoints<TUser>.Refresh);

        endpoints.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization();
    }
}
