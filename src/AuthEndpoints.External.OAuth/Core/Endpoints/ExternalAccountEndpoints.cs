using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Account endpoints for linking / unlinking external logins while signed in.
/// </summary>
public static class ExternalAccountEndpoints<TUser>
    where TUser : class, new()
{
    public static async Task<IResult> ListLogins(UserManager<TUser> userManager, HttpContext httpContext)
    {
        var user = await userManager.GetUserAsync(httpContext.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var logins = await userManager.GetLoginsAsync(user);
        return Results.Ok(logins.Select(l => new ExternalLoginListItem(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName)));
    }

    public static IResult StartLink(
        string scheme,
        [FromQuery] string? returnUrl,
        HttpContext context,
        LinkGenerator linkGenerator,
        SignInManager<TUser> signInManager,
        IEnumerable<IExternalAuthProvider> providers)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return Results.Unauthorized();
        }

        var provider = providers.FirstOrDefault(p => string.Equals(p.Scheme, scheme, StringComparison.Ordinal));
        if (provider is null)
        {
            return Results.Problem(detail: $"Unknown external provider scheme '{scheme}'.", statusCode: StatusCodes.Status400BadRequest);
        }

        var callbackName = LinkCallbackEndpointName(provider.Scheme);
        var callbackPath = linkGenerator.GetPathByName(context, callbackName);
        if (string.IsNullOrEmpty(callbackPath))
        {
            return Results.Problem(
                detail: $"Link callback endpoint '{callbackName}' was not found. Call MapExternalAccountEndpoints.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        var redirectUri = string.IsNullOrEmpty(returnUrl)
            ? callbackPath
            : $"{callbackPath}?returnUrl={Uri.EscapeDataString(returnUrl)}";

        var properties = signInManager.ConfigureExternalAuthenticationProperties(provider.Scheme, redirectUri);
        return Results.Challenge(properties, [provider.Scheme]);
    }

    public static async Task<IResult> LinkCallback(
        string scheme,
        [FromQuery] string? returnUrl,
        [FromQuery] string? error,
        [FromQuery] string? error_description,
        SignInManager<TUser> signInManager,
        UserManager<TUser> userManager,
        IOptions<ExternalAuthOptions> options,
        HttpContext httpContext)
    {
        var opts = options.Value;

        if (!string.IsNullOrEmpty(error))
        {
            return ExternalAuthErrorResults.Create(
                httpContext,
                opts,
                error,
                error_description ?? "The external provider returned an error.",
                StatusCodes.Status400BadRequest);
        }

        var user = await userManager.GetUserAsync(httpContext.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var info = await signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            return ExternalAuthErrorResults.Create(
                httpContext,
                opts,
                "external_login_info_missing",
                "External login information was not found.",
                StatusCodes.Status400BadRequest);
        }

        if (!string.Equals(info.LoginProvider, scheme, StringComparison.Ordinal))
        {
            return ExternalAuthErrorResults.Create(
                httpContext,
                opts,
                "provider_mismatch",
                "External login provider does not match the link route.",
                StatusCodes.Status400BadRequest);
        }

        var result = await userManager.AddLoginAsync(user, info);
        if (!result.Succeeded)
        {
            return ExternalAuthErrorResults.Create(
                httpContext,
                opts,
                "login_link_failed",
                string.Join(" ", result.Errors.Select(e => e.Description)),
                StatusCodes.Status400BadRequest);
        }

        await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        var redirectUrl = ExternalAuthReturnUrl.Resolve(
            returnUrl,
            opts.DefaultReturnUrl,
            opts.AllowedReturnUrlOrigins.ToList());

        return Results.Redirect(redirectUrl);
    }

    public static async Task<IResult> RemoveLogin(
        [FromRoute] string loginProvider,
        [FromRoute] string providerKey,
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        HttpContext httpContext)
    {
        var user = await userManager.GetUserAsync(httpContext.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var result = await userManager.RemoveLoginAsync(user, loginProvider, providerKey);
        if (!result.Succeeded)
        {
            return Results.Problem(
                detail: string.Join(" ", result.Errors.Select(e => e.Description)),
                statusCode: StatusCodes.Status400BadRequest);
        }

        await signInManager.RefreshSignInAsync(user);
        return Results.NoContent();
    }

    internal static string LinkCallbackEndpointName(string scheme) => $"ExternalLinkCallback-{scheme}";
}

/// <summary>
/// External login list item DTO.
/// </summary>
public sealed record ExternalLoginListItem(string LoginProvider, string ProviderKey, string? ProviderDisplayName);
