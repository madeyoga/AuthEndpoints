using System.Security.Claims;
using AuthEndpoints.Core;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.Session;

public class Endpoints<TKey, TUser> : IEndpointDefinition
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>
{
    public void MapEndpoints(WebApplication app)
    {
        app.MapPost("auth/login", Login).WithTags("Auth");
        app.MapGet("auth/logout", Logout).WithTags("Auth");
    }

    public virtual async Task<IResult> Login([FromBody] LoginRequest requestBody,
                                             HttpContext context,
                                             UserManager<TUser> userManager,
                                             IAuthenticator<TUser> authenticator)
    {
        var user = await authenticator.Authenticate(requestBody.Username!, requestBody.Password!);

        if (user == null)
        {
            // Not found
            return Results.BadRequest("Invalid username or password");
        }

        if (await userManager.AccessFailedAsync(user) != IdentityResult.Success)
        {
            return Results.StatusCode(StatusCodes.Status423Locked);
        }

        var claims = new List<Claim>
        {
            new Claim("id", user.Id.ToString()!),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()!),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.GivenName, user.UserName),

            // Here we set the "LastChanged" claim (with the last updated timestamp, for instance)
            //new Claim(SecurityCookieAuthenticationEvents.LastChangedClaim, user.LastChanged.ToString())
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                  new ClaimsPrincipal(claimsIdentity),
                                  new AuthenticationProperties { IsPersistent = true });

        return Results.NoContent();
    }

    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public virtual async Task<IResult> Logout(IHttpContextAccessor contextAccessor)
    {
        var context = contextAccessor.HttpContext!;
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return Results.NoContent();
    }
}
