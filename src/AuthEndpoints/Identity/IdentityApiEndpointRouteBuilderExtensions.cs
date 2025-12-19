using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class IdentityApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps AuthEndpoints version of <c>MapIdentityApi</c>.
    /// This method copy parts of the built-in IdentityApiEndpoints
    /// and add more features to it.
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="endpoints"></param>
    public static IEndpointConventionBuilder MapBearerAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/register", IdentityApiEndpoints<TUser>.Register)
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.");

        routeGroup.MapPost("/login", IdentityApiEndpoints<TUser>.Login);
        routeGroup.MapPost("/refresh", IdentityApiEndpoints<TUser>.Refresh);
        
        routeGroup.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization();
        routeGroup.MapPost("/confirmIdentity", IdentityApiEndpoints<TUser>.ConfirmIdentity)
            .WithSummary("Confirm the user's identity and issue a short-lived reauthentication cookie.")
            .WithDescription("""
            Verifies the current user's identity using either their password or a two-factor authentication (2FA) code. 
            If successful, the endpoint issues a temporary authentication cookie under the reauthentication scheme.
            The cookie is valid for 5 minutes and can be used to authorize sensitive actions
            such as enabling/disabling 2FA, changing the password, or updating other security settings.
            """)
            .RequireAuthorization();

        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            .Add(endpointBuilder =>
            {
                var finalPattern = ((RouteEndpointBuilder)endpointBuilder).RoutePattern.RawText;
                IdentityApiEndpoints<TUser>.ConfirmEmailEndpointName = $"{nameof(MapBearerAuthEndpoints)}-{finalPattern}";
                endpointBuilder.Metadata.Add(new EndpointNameMetadata(IdentityApiEndpoints<TUser>.ConfirmEmailEndpointName));
            });

        routeGroup.MapPost("/resendConfirmationEmail", IdentityApiEndpoints<TUser>.ResendConfirmationEmail)
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
        accountGroup.MapPost("/info", IdentityApiEndpoints<TUser>.ManageInfoPost)
            .WithSummary("Updates the current user account information.");

        return routeGroup;
    }

    /// <summary>
    /// Maps AuthEndpoints version of <c>MapIdentityApi</c>.
    /// This method copy parts of the built-in IdentityApiEndpoints
    /// and add more features to it.
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="endpoints"></param>
    public static IEndpointConventionBuilder MapCookieAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/register", IdentityApiEndpoints<TUser>.Register)
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.");

        routeGroup.MapPost("/login", IdentityApiEndpoints<TUser>.Login)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);
        
        routeGroup.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization()
            .RequireAntiforgery();

        routeGroup.MapGet("/csrfToken", IdentityApiEndpoints<TUser>.GetAntiforgeryToken);
        routeGroup.MapPost("/confirmIdentity", IdentityApiEndpoints<TUser>.ConfirmIdentity)
            .WithSummary("Confirm the user's identity and issue a short-lived reauthentication cookie.")
            .WithDescription("""
            Verifies the current user's identity using either their password or a two-factor authentication (2FA) code. 
            If successful, the endpoint issues a temporary authentication cookie under the reauthentication scheme.
            The cookie is valid for 5 minutes and can be used to authorize sensitive actions
            such as enabling/disabling 2FA, changing the password, or updating other security settings.
            """)
            .RequireAuthorization()
            .RequireAntiforgery();

        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            // .WithName(IdentityApiEndpoints<TUser>.confirmEmailEndpointName)
            .Add(endpointBuilder =>
            {
                var finalPattern = ((RouteEndpointBuilder)endpointBuilder).RoutePattern.RawText;
                IdentityApiEndpoints<TUser>.ConfirmEmailEndpointName = $"{nameof(MapCookieAuthEndpoints)}-{finalPattern}";
                endpointBuilder.Metadata.Add(new EndpointNameMetadata(IdentityApiEndpoints<TUser>.ConfirmEmailEndpointName));
            });

        routeGroup.MapPost("/resendConfirmationEmail", IdentityApiEndpoints<TUser>.ResendConfirmationEmail)
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
        accountGroup.MapPost("/info", IdentityApiEndpoints<TUser>.ManageInfoPost)
            .WithSummary("Updates the current user account information.")
            .RequireAntiforgery();

        return routeGroup;
    }
}
