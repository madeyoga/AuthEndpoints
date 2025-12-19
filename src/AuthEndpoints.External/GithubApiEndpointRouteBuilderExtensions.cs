using System.Security.Claims;
using AspNet.Security.OAuth.GitHub;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.External;

public static class GithubApiEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapGithubAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var group = endpoints.MapGroup("");

        group.MapGet("/login/github",
            ([FromQuery] string returnUrl, HttpContext context, LinkGenerator linkGenerator, SignInManager<TUser> signInManager) =>
        {
            var scheme = GitHubAuthenticationDefaults.AuthenticationScheme;
            var properties = signInManager.ConfigureExternalAuthenticationProperties(
                scheme,
                linkGenerator.GetPathByName(context, "GithubLoginCallback") + $"?returnUrl={returnUrl}"
            );
            return Results.Challenge(properties, [scheme]);
        });

        /// Using signInManager.GetExternalLoginInfoAsync();
        /// Require GithubAuthenticationOptions.SignInScheme set to IdentityConstants.ExternalScheme
        group.MapGet("/login/github/callback", async
            ([FromQuery] string returnUrl, 
            HttpContext context, 
            [FromServices] SignInManager<TUser> signInManager, 
            [FromServices] UserManager<TUser> userManager,
            [FromServices] IUserEmailStore<TUser> userEmailStore,
            [FromServices] IUserStore<TUser> userStore) =>
        {
            // Authenticate with IdentityConstants.ExternalScheme and get ExternalLoginInfo (UserLoginInfo with claimsprinciple and extra auth properties)
            var info = await signInManager.GetExternalLoginInfoAsync();

            if (info == null)
            {
                return Results.BadRequest("null external login info");
            }

            // Try SignIn using external login info and issue cookie
            var signInResult = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: true, bypassTwoFactor: true);

            if (signInResult.Succeeded)
            {
                return Results.Redirect(returnUrl);
            }

            // If failed, Get and manually signin user

            var principal = info.Principal;

            var email = principal.FindFirstValue(ClaimTypes.Email);

            if (email == null)
            {
                return Results.Problem("null email");
            }

            // Create new user if not exists
            var user = await userManager.FindByEmailAsync(email);

            if (user == null)
            {
                user = new TUser();
                await userStore.SetUserNameAsync(user, email, CancellationToken.None);
                await userEmailStore.SetEmailAsync(user, email, CancellationToken.None);

                var createUserResult = await userManager.CreateAsync(user);

                if (!createUserResult.Succeeded)
                {
                    return Results.Problem(
                        detail: "Error: Could not create a new user.",
                        statusCode: StatusCodes.Status400BadRequest
                    );
                }

                // Map github login to user
                // Save AspNetUserLogin entry to database
                var linkAccountResult = await userManager.AddLoginAsync(user, info);

                if (!linkAccountResult.Succeeded)
                {
                    return Results.Problem(
                        detail: "Error: Unable to link Github account.",
                        statusCode: StatusCodes.Status400BadRequest
                    );
                }
            }

            // Issue cookie
            await signInManager.SignInAsync(user, isPersistent: true);

            return Results.Redirect(returnUrl);
        }).WithName("GithubLoginCallback");

        return group;
    }
}
