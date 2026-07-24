using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class IdentityApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps AuthEndpoints version of <c>MapIdentityApi</c>.
    /// This method copy parts of the built-in IdentityApiEndpoints
    /// and add more features to it.
    /// </summary>
    public static IEndpointConventionBuilder MapBearerAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");
        var confirmEmailEndpointName = $"{nameof(MapBearerAuthEndpoints)}-{typeof(TUser).Name}-confirmEmail";

        routeGroup.MapPost("/register", (
            RegisterRequest registration,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.Register(registration, context, sp, confirmEmailEndpointName))
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.");

        routeGroup.MapPost("/login", IdentityApiEndpoints<TUser>.Login);
        routeGroup.MapPost("/refresh", IdentityApiEndpoints<TUser>.Refresh);

        routeGroup.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization();

        routeGroup.MapReAuthEndpoints<TUser>(requireAntiforgery: false);

        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            .WithName(confirmEmailEndpointName);

        routeGroup.MapPost("/resendConfirmationEmail", (
            ResendConfirmationEmailRequest resendRequest,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.ResendConfirmationEmail(resendRequest, context, sp, confirmEmailEndpointName))
            .WithSummary("Resends the confirmation email for an unverified account.")
            .RequireAuthorization();

        routeGroup.MapPost("/forgotPassword", IdentityApiEndpoints<TUser>.ForgotPassword)
            .WithSummary("Sends a password reset email to the user.");

        routeGroup.MapPost("/resetPassword", IdentityApiEndpoints<TUser>.ResetPassword)
            .WithSummary("Resets the user's password using the provided token.");

        var accountGroup = routeGroup.MapGroup("/manage").RequireAuthorization();

        accountGroup.MapGet("/2fa", IdentityApiEndpoints<TUser>.TwoFactorStatus)
            .WithSummary("Get two-factor authentication status.");
        accountGroup.MapPost("/2fa", IdentityApiEndpoints<TUser>.ManageTwoFactor)
            .WithSummary("Enables or disables two-factor authentication.");
        accountGroup.MapGet("/info", IdentityApiEndpoints<TUser>.ManageInfoGet);
        accountGroup.MapPost("/info", (
            System.Security.Claims.ClaimsPrincipal claimsPrincipal,
            InfoRequest infoRequest,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.ManageInfoPost(claimsPrincipal, infoRequest, context, sp, confirmEmailEndpointName))
            .WithSummary("Updates the current user account information.");

        return routeGroup;
    }

    /// <summary>
    /// Maps AuthEndpoints version of <c>MapIdentityApi</c>.
    /// This method copy parts of the built-in IdentityApiEndpoints
    /// and add more features to it.
    /// </summary>
    public static IEndpointConventionBuilder MapCookieAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");
        var confirmEmailEndpointName = $"{nameof(MapCookieAuthEndpoints)}-{typeof(TUser).Name}-confirmEmail";

        routeGroup.MapPost("/register", (
            RegisterRequest registration,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.Register(registration, context, sp, confirmEmailEndpointName))
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.");

        routeGroup.MapPost("/login", IdentityApiEndpoints<TUser>.LoginCookie)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);

        routeGroup.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization()
            .RequireAntiforgery();

        routeGroup.MapGet("/csrfToken", IdentityApiEndpoints<TUser>.GetAntiforgeryToken);

        routeGroup.MapReAuthEndpoints<TUser>(requireAntiforgery: true);

        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            .WithName(confirmEmailEndpointName);

        routeGroup.MapPost("/resendConfirmationEmail", (
            ResendConfirmationEmailRequest resendRequest,
            HttpContext context,
            IServiceProvider sp) => IdentityApiEndpoints<TUser>.ResendConfirmationEmail(resendRequest, context, sp, confirmEmailEndpointName))
            .RequireAuthorization()
            .RequireAntiforgery()
            .WithSummary("Resends the confirmation email for an unverified account.");

        routeGroup.MapPost("/forgotPassword", IdentityApiEndpoints<TUser>.ForgotPassword)
            .WithSummary("Sends a password reset email to the user.");

        routeGroup.MapPost("/resetPassword", IdentityApiEndpoints<TUser>.ResetPassword)
            .WithSummary("Resets the user's password using the provided token.");

        var accountGroup = routeGroup.MapGroup("/manage").RequireAuthorization();

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
            .RequireAntiforgery();

        return routeGroup;
    }
}
