using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class IdentityApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps Identity account management endpoints for user registration and profile management,
    /// excluding the built-in <c>/login</c> authentication endpoint.
    /// This method copy parts of the built-in Identity Api
    /// but include only user and account management features.
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="endpoints"></param>
    public static IEndpointRouteBuilder MapAuthEndpointsIdentityApi<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/register", IdentityApiEndpoints<TUser>.Register)
            .WithSummary("Registers a new user account.")
            .WithDescription("Creates a new user and sends a confirmation email if enabled.");

        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithSummary("Confirms a user's email address.")
            .WithDescription("Validates the email confirmation token and activates the account.")
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
    /// Maps the built-in Identity Api endpoints and adds an additional <c>/logout</c> endpoint 
    /// for cookie based authentication. 
    /// When <c>useCookies=true</c> is passed to the <c>/login</c> endpoint, tokens are stored in cookies instead of being returned to the client. 
    /// This logout endpoint clears those cookies by signing out from Identity authentication schemes
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="endpoints"></param>
    public static IEndpointRouteBuilder MapIdentityApiFull<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");
        
        routeGroup.MapPost("/logout", IdentityApiEndpoints<TUser>.Logout)
            .WithSummary("Clear cookies and logout user")
            .RequireAuthorization();
        routeGroup.MapIdentityApi<TUser>();

        return routeGroup;
    }
}
