using System.Security.Claims;
using AuthEndpoints.EmailCode;
using AuthEndpoints.ReAuth;
using AuthEndpoints.SignIn;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

internal static class IdentityEndpointRoutes
{
    public static void MapRegister<TUser>(IEndpointRouteBuilder endpoints, string confirmEmailEndpointName, string mapMethod)
        where TUser : class, new()
    {
        endpoints.MapPost("/register", (
            RegisterRequest registration,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.Register(registration, context, sp, confirmEmailEndpointName))
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy)
            .Track(endpoints, mapMethod);
    }

    public static void MapPasswordLogin<TUser>(
        IEndpointRouteBuilder endpoints,
        PasswordLoginMode login,
        string mapMethod,
        string? completer = null)
        where TUser : class, new()
    {
        if (completer is not null)
        {
            SignInCompleterMap.EnsureSelected<TUser>(endpoints, completer, mapMethod);
            endpoints.MapPost("/login", (
                    [FromBody] LoginRequest loginRequest,
                    [FromQuery] bool? useCookies,
                    [FromQuery] bool? useSessionCookies,
                    HttpContext httpContext) => PasswordCompleterSignIn<TUser>.Handle(
                        loginRequest,
                        useCookies,
                        useSessionCookies,
                        httpContext,
                        completer))
                .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
                .WithMetadata(new SignInCompleterSelection(completer))
                .Track(endpoints, mapMethod);
            return;
        }

        switch (login)
        {
            case PasswordLoginMode.None:
                return;
            case PasswordLoginMode.Cookie:
                endpoints.MapPost("/login", IdentityApiEndpoints<TUser>.LoginCookie)
                    .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
                    .Track(endpoints, mapMethod);
                return;
            case PasswordLoginMode.IdentityBearer:
                endpoints.MapPost("/login", IdentityApiEndpoints<TUser>.Login)
                    .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
                    .Track(endpoints, mapMethod);
                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(login), login, "Unknown password login mode.");
        }
    }

    public static void MapForgotPassword<TUser>(IEndpointRouteBuilder endpoints, string mapMethod)
        where TUser : class, new()
    {
        endpoints.MapPost("/forgotPassword", IdentityApiEndpoints<TUser>.ForgotPassword)
            .WithSummary("Sends a password reset email to the user.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy)
            .Track(endpoints, mapMethod);
    }

    public static void MapResetPassword<TUser>(IEndpointRouteBuilder endpoints, string mapMethod)
        where TUser : class, new()
    {
        endpoints.MapPost("/resetPassword", IdentityApiEndpoints<TUser>.ResetPassword)
            .WithSummary("Resets the user's password using the provided token.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy)
            .Track(endpoints, mapMethod);
    }

    public static IEndpointConventionBuilder MapConfirmEmail<TUser>(IEndpointRouteBuilder endpoints, string confirmEmailEndpointName, string mapMethod)
        where TUser : class, new()
    {
        // Map on the caller's builder. A nested group would land in a later data source, so
        // confirm and resend would follow forgot and reset instead of the 3.3.0 order.
        var confirm = endpoints.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            .WithName(confirmEmailEndpointName)
            .Track(endpoints, mapMethod);

        var resend = endpoints.MapPost("/resendConfirmationEmail", (
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
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy)
            .Track(endpoints, mapMethod);

        return new CompositeEndpointConventionBuilder(confirm, resend);
    }

    public static void MapConfirmIdentity<TUser>(IEndpointRouteBuilder endpoints, bool requireAntiforgery, string mapMethod)
        where TUser : class, new()
    {
        var confirm = endpoints.MapPost("/confirmIdentity", ReAuthEndpoints<TUser>.ConfirmIdentity)
            .WithSummary("Confirm the user's identity and issue short-lived reauthentication credentials.")
            .WithDescription("""
                Provide exactly one proof: Password, TwoFactorCode, TwoFactorRecoveryCode, CredentialJson (passkey assertion), or EmailCode.
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

        confirm.Track(endpoints, mapMethod);
    }

    public static void MapEmailCodeReAuthSend<TUser>(IEndpointRouteBuilder endpoints, bool requireAntiforgery, string mapMethod)
        where TUser : class, new()
    {
        if (endpoints.ServiceProvider.GetService<IEmailCodeModelCheck>() is null)
        {
            return;
        }

        var send = endpoints.MapPost("/confirmIdentity/emailCode/send", ReAuthEndpoints<TUser>.SendEmailCode)
            .WithSummary("Send an email code that confirms the signed-in user's identity.")
            .WithDescription("""
                No body. Sends a code to the signed-in user's current confirmed email when email-code step-up is available.
                Returns expiresInSeconds and resendAfterSeconds. Does not sign the user in.
                """)
            .RequireAuthEndpointsUser()
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityEmailCodePolicy);

        if (requireAntiforgery)
        {
            send.RequireAntiforgery();
        }

        send.Track(endpoints, mapMethod);
    }

    public static void MapPasskeyOptions<TUser>(IEndpointRouteBuilder endpoints, bool requireAntiforgery, string mapMethod)
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

        passkeyOptions.Track(endpoints, mapMethod);
    }

    public static void MapAuthMethods<TUser>(IEndpointRouteBuilder endpoints, string mapMethod)
        where TUser : class, new()
    {
        var manage = endpoints.MapGroup("/manage").RequireAuthEndpointsUser();
        manage.MapGet("/authMethods", ReAuthEndpoints<TUser>.AuthMethods)
            .WithSummary("List available step-up / reauthentication methods for the current user.")
            .Track(endpoints, mapMethod);
    }

    public static void MapManageInfoAndTwoFactor<TUser>(IEndpointRouteBuilder endpoints, string confirmEmailEndpointName, string mapMethod)
        where TUser : class, new()
    {
        var accountGroup = endpoints.MapGroup("/manage").RequireAuthEndpointsUser();

        accountGroup.MapGet("/2fa", IdentityApiEndpoints<TUser>.TwoFactorStatus)
            .WithSummary("Get two-factor authentication status.")
            .Track(endpoints, mapMethod);
        accountGroup.MapPost("/2fa", IdentityApiEndpoints<TUser>.ManageTwoFactor)
            .WithSummary("Enables or disables two-factor authentication.")
            .RequireAntiforgery()
            .RequireReauth()
            .Track(endpoints, mapMethod);
        accountGroup.MapGet("/info", IdentityApiEndpoints<TUser>.ManageInfoGet)
            .Track(endpoints, mapMethod);
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
            .RequireReauth()
            .Track(endpoints, mapMethod);
    }

    public static void MapCookieSession<TUser>(IEndpointRouteBuilder endpoints, string mapMethod)
        where TUser : class, new()
    {
        endpoints.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization()
            .RequireAntiforgery()
            .Track(endpoints, mapMethod);

        endpoints.MapGet("/csrfToken", IdentityApiEndpoints<TUser>.GetAntiforgeryToken)
            .Track(endpoints, mapMethod);
    }

    public static void MapBearerSession<TUser>(IEndpointRouteBuilder endpoints, string mapMethod)
        where TUser : class, new()
    {
        endpoints.MapPost("/refresh", IdentityApiEndpoints<TUser>.Refresh)
            .Track(endpoints, mapMethod);

        endpoints.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization()
            .Track(endpoints, mapMethod);
    }
}
