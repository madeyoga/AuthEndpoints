using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class IdentityApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps account lifecycle endpoints (register, confirm/resend, forgot/reset, manage, ReAuth).
    /// Compose with <see cref="MapCookieAuthEndpoints{TUser}"/>, <see cref="MapBearerAuthEndpoints{TUser}"/>,
    /// or <c>MapJwtAuthEndpoints</c> for sign-in. Call <c>UseRateLimiter()</c> and <c>UseAntiforgery()</c>.
    /// </summary>
    /// <param name="confirmEmailEndpointName">
    /// Optional unique endpoint name for confirm-email link generation.
    /// Required when mapping management more than once in the same app.
    /// </param>
    public static IEndpointConventionBuilder MapIdentityManagementApi<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeGroup = endpoints.MapGroup("");
        var authorize = ManagementAuthorization.CreateAuthorizeAttribute(endpoints);
        confirmEmailEndpointName ??= DefaultConfirmEmailEndpointName<TUser>();

        routeGroup.MapPost("/register", (
            RegisterRequest registration,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.Register(registration, context, sp, confirmEmailEndpointName))
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy);

        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            .WithName(confirmEmailEndpointName);

        routeGroup.MapPost("/resendConfirmationEmail", (
            ResendConfirmationEmailRequest resendRequest,
            System.Security.Claims.ClaimsPrincipal claimsPrincipal,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.ResendConfirmationEmail(resendRequest, claimsPrincipal, context, sp, confirmEmailEndpointName))
            .WithSummary("Resends the confirmation email for the signed-in account.")
            .RequireAuthorization(authorize)
            .RequireAntiforgery()
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy);

        routeGroup.MapPost("/forgotPassword", IdentityApiEndpoints<TUser>.ForgotPassword)
            .WithSummary("Sends a password reset email to the user.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy);

        routeGroup.MapPost("/resetPassword", IdentityApiEndpoints<TUser>.ResetPassword)
            .WithSummary("Resets the user's password using the provided token.")
            .RequireRateLimiting(AuthEndpointsConstants.AccountAbusePolicy);

        routeGroup.MapReAuthEndpoints<TUser>(requireAntiforgery: true);

        var accountGroup = routeGroup.MapGroup("/manage").RequireAuthorization(authorize);

        accountGroup.MapGet("/2fa", IdentityApiEndpoints<TUser>.TwoFactorStatus)
            .WithSummary("Get two-factor authentication status.");
        accountGroup.MapPost("/2fa", IdentityApiEndpoints<TUser>.ManageTwoFactor)
            .WithSummary("Enables or disables two-factor authentication.")
            .RequireAntiforgery()
            .RequireReauth();
        accountGroup.MapGet("/info", IdentityApiEndpoints<TUser>.ManageInfoGet);
        accountGroup.MapPost("/info", (
            System.Security.Claims.ClaimsPrincipal claimsPrincipal,
            InfoRequest infoRequest,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.ManageInfoPost(claimsPrincipal, infoRequest, context, sp, confirmEmailEndpointName))
            .WithSummary("Updates the current user account information.")
            .RequireAntiforgery()
            .RequireReauth();

        return routeGroup;
    }

    internal static string DefaultConfirmEmailEndpointName<TUser>() where TUser : class
        => $"{nameof(MapIdentityManagementApi)}-{typeof(TUser).Name}-confirmEmail";

    /// <summary>
    /// Maps Identity bearer sign-in endpoints (login, refresh, logout).
    /// Pair with <see cref="MapIdentityManagementApi{TUser}"/> for register/manage.
    /// Call <see cref="ServiceCollectionExtensions.AddBearerAuthEndpoints"/> and <c>UseRateLimiter()</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapBearerAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/login", IdentityApiEndpoints<TUser>.Login)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);
        routeGroup.MapPost("/refresh", IdentityApiEndpoints<TUser>.Refresh);

        routeGroup.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization();

        return routeGroup;
    }

    /// <summary>
    /// Maps Identity cookie sign-in endpoints (login, logout, csrfToken).
    /// Pair with <see cref="MapIdentityManagementApi{TUser}"/> for register/manage.
    /// Call <see cref="ServiceCollectionExtensions.AddCookieAuthEndpoints"/> and <c>UseRateLimiter()</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapCookieAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/login", IdentityApiEndpoints<TUser>.LoginCookie)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);

        routeGroup.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization()
            .RequireAntiforgery();

        routeGroup.MapGet("/csrfToken", IdentityApiEndpoints<TUser>.GetAntiforgeryToken);

        return routeGroup;
    }
}
