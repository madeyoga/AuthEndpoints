using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class IdentityApiEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapIdentityApi<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/register", IdentityApiEndpoints<TUser>.Register);
        routeGroup.MapGet("/confirmEmail", IdentityApiEndpoints<TUser>.ConfirmEmail)
            .WithName(IdentityApiEndpoints<TUser>.confirmEmailEndpointName);
        routeGroup.MapPost("/resendConfirmationEmail", IdentityApiEndpoints<TUser>.ResendConfirmationEmail);
        routeGroup.MapPost("/forgotPassword", IdentityApiEndpoints<TUser>.ForgotPassword);
        routeGroup.MapPost("/resetPassword", IdentityApiEndpoints<TUser>.ResetPassword);

        var accountGroup = routeGroup.MapGroup("/manage").RequireAuthorization();

        accountGroup.MapPost("/2fa", IdentityApiEndpoints<TUser>.ManageTwoFactor);
        accountGroup.MapGet("/info", IdentityApiEndpoints<TUser>.ManageInfoGet);
        accountGroup.MapPost("/info", IdentityApiEndpoints<TUser>.ManageInfoPost);

        return routeGroup;
    }
}
