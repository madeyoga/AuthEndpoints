using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Shared external auth endpoint handlers used by all provider modules.
/// </summary>
public static class ExternalAuthEndpoints<TUser>
    where TUser : class, new()
{
    public static IResult Login(
        [FromQuery] string? returnUrl,
        HttpContext context,
        LinkGenerator linkGenerator,
        SignInManager<TUser> signInManager,
        IExternalAuthProvider provider)
    {
        var callbackPath = linkGenerator.GetPathByName(context, provider.CallbackEndpointName);
        if (string.IsNullOrEmpty(callbackPath))
        {
            return Results.Problem(
                detail: $"Callback endpoint '{provider.CallbackEndpointName}' was not found.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        var redirectUri = string.IsNullOrEmpty(returnUrl)
            ? callbackPath
            : $"{callbackPath}?returnUrl={Uri.EscapeDataString(returnUrl)}";

        var properties = signInManager.ConfigureExternalAuthenticationProperties(provider.Scheme, redirectUri);
        return Results.Challenge(properties, [provider.Scheme]);
    }

    public static async Task<IResult> Callback(
        [FromQuery] string? returnUrl,
        [FromQuery] string? error,
        [FromQuery] string? error_description,
        ExternalLoginService<TUser> loginService,
        IExternalLoginCompleter<TUser> completer,
        IOptions<ExternalAuthOptions> options,
        HttpContext httpContext,
        CancellationToken cancellationToken)
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

        var provision = await loginService.ProvisionAsync(cancellationToken);
        if (!provision.Succeeded)
        {
            return ExternalAuthErrorResults.Create(
                httpContext,
                opts,
                provision.Error!,
                provision.ErrorDescription!,
                provision.StatusCode);
        }

        return await completer.CompleteAsync(
            httpContext,
            provision.User!,
            provision.Info!,
            returnUrl,
            cancellationToken);
    }
}
