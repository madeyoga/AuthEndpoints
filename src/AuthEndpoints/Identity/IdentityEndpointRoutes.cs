using System.Security.Claims;
using AuthEndpoints.EmailCode;
using AuthEndpoints.ReAuth;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

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
            .WithDescription("Creates a new user and sends a confirmation email. An email that is already registered returns the same empty 200 and emails that owner.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy)
            .Track(endpoints, mapMethod);
    }

    public static void MapPasswordLogin<TUser>(
        IEndpointRouteBuilder endpoints,
        PasswordLoginMode login,
        string mapMethod,
        string? completer = null,
        bool allowUnregisteredBuiltIn = false)
        where TUser : class, new()
    {
        if (completer is not null)
        {
            if (!allowUnregisteredBuiltIn
                || SignInCompleterRegistry.Contains<TUser>(endpoints.ServiceProvider, completer))
            {
                SignInCompleterMap.EnsureSelected<TUser>(endpoints, completer, mapMethod);
            }
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
            PasswordSignInMap.Mark(endpoints.ServiceProvider);
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
                PasswordSignInMap.Mark(endpoints.ServiceProvider);
                return;
            case PasswordLoginMode.IdentityBearer:
                endpoints.MapPost("/login", IdentityApiEndpoints<TUser>.Login)
                    .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
                    .Track(endpoints, mapMethod);
                PasswordSignInMap.Mark(endpoints.ServiceProvider);
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

    /// <summary>
    /// Maps external-provider step-up when external sign-in is registered:
    /// start, launch, callback and the bearer code exchange.
    /// </summary>
    public static void MapExternalReAuth<TUser>(IEndpointRouteBuilder endpoints, bool requireAntiforgery, string mapMethod)
        where TUser : class, new()
    {
        if (!AuthEndpointsModules.IsRegistered<External.OAuth.ExternalAuthEndpointsModule>(endpoints.ServiceProvider))
        {
            return;
        }

        var marker = endpoints.ServiceProvider.GetRequiredService<ExternalReAuthMapMarker>();
        if (marker.Mapped)
        {
            return;
        }

        marker.Mapped = true;

        var complete = endpoints.MapPost("/confirmIdentity/external/complete", ExternalReAuthEndpoints<TUser>.Complete)
            .WithSummary("Exchange a one-time external step-up code for a reauthToken.")
            .WithDescription("For bearer clients. Send the reauthCode from the step-up return URL. Returns reauthToken.")
            .RequireAuthEndpointsUser()
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityPolicy);

        var start = endpoints.MapPost("/confirmIdentity/external/{provider}", ExternalReAuthEndpoints<TUser>.Start)
            .WithSummary("Start confirming the user's identity with a fresh sign-in at a linked external provider.")
            .WithDescription("""
                Returns redirectUrl. Navigate the browser there to sign in at the provider.
                Cookie sign-ins come back with the AuthEndpoints.ReAuth cookie.
                Bearer clients come back with a one-time reauthCode to exchange at /confirmIdentity/external/complete.
                """)
            .RequireAuthEndpointsUser()
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityPolicy);

        if (requireAntiforgery)
        {
            complete.RequireAntiforgery();
            start.RequireAntiforgery();
        }

        endpoints.MapGet("/confirmIdentity/external/{provider}/launch", ExternalReAuthEndpoints<TUser>.Launch)
            .WithSummary("Redirect to the external provider for step-up.")
            .WithName(ExternalReAuthEndpoints<TUser>.LaunchEndpointName)
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityPolicy)
            .Track(endpoints, mapMethod);

        endpoints.MapGet("/confirmIdentity/external/{provider}/callback", ExternalReAuthEndpoints<TUser>.Callback)
            .WithSummary("Complete external-provider step-up.")
            .WithName(ExternalReAuthEndpoints<TUser>.CallbackEndpointName)
            .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityPolicy)
            .Track(endpoints, mapMethod);

        complete.Track(endpoints, mapMethod);
        start.Track(endpoints, mapMethod);
    }

    public static void MapEmailCodeReAuthSend<TUser>(IEndpointRouteBuilder endpoints, bool requireAntiforgery, string mapMethod)
        where TUser : class, new()
    {
        // Send owns this route and AuthEndpoints.ConfirmIdentity.EmailCode.
        // Sign-in shares the store, and it does not register that policy.
        if (!AuthEndpointsModules.IsRegistered<EmailCodeSendEndpointsModule>(endpoints.ServiceProvider))
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

    public static void MapAuthMethods<TUser>(IEndpointRouteBuilder endpoints, string mapMethod, bool includeEmailCode = true)
        where TUser : class, new()
    {
        var manage = endpoints.MapGroup("/manage").RequireAuthEndpointsUser();
        RouteHandlerBuilder authMethods = includeEmailCode
            ? manage.MapGet("/authMethods", (
                ClaimsPrincipal principal,
                UserManager<TUser> userManager,
                IServiceProvider services) => ReAuthEndpoints<TUser>.AuthMethods(principal, userManager, services))
            : manage.MapGet("/authMethods", (
                ClaimsPrincipal principal,
                UserManager<TUser> userManager,
                IServiceProvider services) => ReAuthEndpoints<TUser>.ListAuthMethods(
                    principal, userManager, includeEmailCode: false, services));
        authMethods
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
        accountGroup.MapPost("/2fa", (
            ClaimsPrincipal claimsPrincipal,
            [FromBody] TwoFactorRequest tfaRequest,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.ManageTwoFactor(claimsPrincipal, tfaRequest, sp, context))
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

    public static void MapSetPassword<TUser>(IEndpointRouteBuilder endpoints, string mapMethod)
        where TUser : class, new()
    {
        var accountGroup = endpoints.MapGroup("/manage").RequireAuthEndpointsUser();
        accountGroup.MapPost("/password", IdentityApiEndpoints<TUser>.SetPassword)
            .WithSummary("Sets a password when the account has none.")
            .WithDescription("""
                Requires a signed-in user, antiforgery, and a ReAuth proof.
                Rate-limited with the account-abuse policy.
                Returns 404 when password sign-in is not mapped.
                Returns 400 when the account already has a password. Change an existing password with POST /manage/info.
                Sends a security email and rotates the security stamp.
                """)
            .RequireAntiforgery()
            .RequireReauth()
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy)
            .WithMetadata(SetPasswordEndpointMetadata.Instance)
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
