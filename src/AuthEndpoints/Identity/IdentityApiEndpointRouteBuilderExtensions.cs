using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class IdentityApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps Identity account management endpoints for user registration and account management,
    /// excluding the built-in <c>/login</c> authentication endpoint.
    /// This method copy parts of the built-in Identity Api
    /// but include only user and account management features.
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="endpoints"></param>
    public static IEndpointConventionBuilder MapAccountApi<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/register", IdentityApiEndpoints<TUser>.Register)
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.");

        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            .WithName(IdentityApiEndpoints<TUser>.confirmEmailEndpointName);

        routeGroup.MapPost("/resendConfirmationEmail", IdentityApiEndpoints<TUser>.ResendConfirmationEmail)
            .WithSummary("Resends the confirmation email for an unverified account.");

        routeGroup.MapPost("/forgotPassword", IdentityApiEndpoints<TUser>.ForgotPassword)
            .WithSummary("Sends a password reset email to the user.");

        routeGroup.MapPost("/resetPassword", IdentityApiEndpoints<TUser>.ResetPassword)
            .WithSummary("Resets the user's password using the provided token.");

        var accountGroup = routeGroup.MapGroup("/manage").RequireAuthorization();

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
    public static IEndpointConventionBuilder MapAuthEndpointsIdentityApi<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/register", IdentityApiEndpoints<TUser>.Register)
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if configured.");

        routeGroup.MapPost("/login", IdentityApiEndpoints<TUser>.Login);
        
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
            .WithName(IdentityApiEndpoints<TUser>.confirmEmailEndpointName);

        routeGroup.MapPost("/resendConfirmationEmail", IdentityApiEndpoints<TUser>.ResendConfirmationEmail)
            .WithSummary("Resends the confirmation email for an unverified account.");

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
    /// Maps the built-in Identity Api endpoints and adds an additional <c>/logout</c> endpoint 
    /// for cookie based authentication. 
    /// When <c>useCookies=true</c> is passed to the <c>/login</c> endpoint, tokens are stored in cookies instead of being returned to the client. 
    /// This logout endpoint clears those cookies by signing out from Identity authentication schemes
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="endpoints"></param>
    public static IEndpointConventionBuilder MapIdentityApiFull<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

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

        return routeGroup.MapIdentityApi<TUser>();
    }
}
