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
            ([FromQuery] string returnUrl, HttpContext context, SignInManager<TUser> signInManager, UserManager<TUser> userManager) =>
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
                // user = new AppUser
                // {
                //     UserName = email,
                //     Email = email,
                //     EmailConfirmed = true,
                //     DisplayName = principal.FindFirstValue("urn:github:name")
                //         ?? principal.FindFirstValue(ClaimTypes.Name)
                //         ?? string.Empty,
                // };

                // var createUserResult = await userManager.CreateAsync(user);

                // if (!createUserResult.Succeeded)
                // {
                //     return Results.Problem(string.Join(", ", createUserResult.Errors.Select(x => x.Description)));
                // }

                // // Map github login to user
                // // Save AspNetUserLogin entry to database
                // var linkAccountResult = await userManager.AddLoginAsync(user, info);

                // if (!linkAccountResult.Succeeded)
                // {
                //     var errors = string.Join(", ", linkAccountResult.Errors.Select(x => x.Description));
                //     return Results.Problem($"Unable to link Github account: {errors}");
                // }
            }

            // Issue cookie
            await signInManager.SignInAsync(user, isPersistent: true);

            return Results.Redirect(returnUrl);
        }).WithName("GithubLoginCallback");

        return group;
    }
}
