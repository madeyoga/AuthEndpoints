using System.Security.Claims;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.ReAuth;

public static class ReAuthEndpoints<TUser>
    where TUser : class, new()
{
    public static async Task<Results<Ok<AuthMethodsResponse>, UnauthorizedHttpResult>> AuthMethods(
        ClaimsPrincipal principal,
        UserManager<TUser> userManager)
    {
        var user = await userManager.GetUserAsync(principal);
        if (user is null)
        {
            return TypedResults.Unauthorized();
        }

        var passkeys = await userManager.GetPasskeysAsync(user);
        var passkeyCount = passkeys.Count;
        var recoveryCodesLeft = await userManager.CountRecoveryCodesAsync(user);

        return TypedResults.Ok(new AuthMethodsResponse(
            Password: await userManager.HasPasswordAsync(user),
            Authenticator: await userManager.GetTwoFactorEnabledAsync(user),
            RecoveryCodes: recoveryCodesLeft > 0,
            Passkeys: passkeyCount > 0,
            PasskeyCount: passkeyCount));
    }

    public static async Task<Results<ContentHttpResult, UnauthorizedHttpResult, NotFound>> PasskeyOptions(
        HttpContext context,
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return TypedResults.Unauthorized();
        }

        var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(user);
        return TypedResults.Content(optionsJson, contentType: "application/json");
    }

    public static async Task<Results<Ok<ConfirmIdentityResponse>, UnauthorizedHttpResult, BadRequest<string>, ProblemHttpResult>> ConfirmIdentity(
        [FromBody] ConfirmIdentityRequest request,
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        HttpContext context)
    {
        var tokenService = context.RequestServices.GetRequiredService<ReAuthTokenService>();
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return TypedResults.Unauthorized();
        }

        var proofCount =
            (string.IsNullOrEmpty(request.Password) ? 0 : 1)
            + (string.IsNullOrEmpty(request.TwoFactorCode) ? 0 : 1)
            + (string.IsNullOrEmpty(request.TwoFactorRecoveryCode) ? 0 : 1)
            + (string.IsNullOrEmpty(request.CredentialJson) ? 0 : 1);

        if (proofCount != 1)
        {
            return TypedResults.BadRequest(
                "Provide exactly one of Password, TwoFactorCode, TwoFactorRecoveryCode, or CredentialJson.");
        }

        var valid = false;

        if (!string.IsNullOrEmpty(request.CredentialJson))
        {
            var assertionResult = await signInManager.PerformPasskeyAssertionAsync(request.CredentialJson);
            if (!assertionResult.Succeeded || assertionResult.User is null)
            {
                return TypedResults.Unauthorized();
            }

            var currentUserId = await userManager.GetUserIdAsync(user);
            var assertedUserId = await userManager.GetUserIdAsync(assertionResult.User);
            if (!string.Equals(currentUserId, assertedUserId, StringComparison.Ordinal))
            {
                return TypedResults.Unauthorized();
            }

            var updateResult = await userManager.AddOrUpdatePasskeyAsync(assertionResult.User, assertionResult.Passkey);
            if (!updateResult.Succeeded)
            {
                return TypedResults.Problem(
                    detail: "Passkey assertion succeeded but the credential could not be updated.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            valid = true;
        }
        else if (!string.IsNullOrEmpty(request.TwoFactorCode))
        {
            if (!await userManager.GetTwoFactorEnabledAsync(user))
            {
                return TypedResults.Unauthorized();
            }

            valid = await userManager.VerifyTwoFactorTokenAsync(
                user,
                userManager.Options.Tokens.AuthenticatorTokenProvider,
                request.TwoFactorCode);
        }
        else if (!string.IsNullOrEmpty(request.TwoFactorRecoveryCode))
        {
            var redeemResult = await userManager.RedeemTwoFactorRecoveryCodeAsync(user, request.TwoFactorRecoveryCode);
            valid = redeemResult.Succeeded;
        }
        else if (!string.IsNullOrEmpty(request.Password))
        {
            var passwordResult = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            valid = passwordResult.Succeeded;
        }

        if (!valid)
        {
            return TypedResults.Unauthorized();
        }

        var authProps = new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        var claims = new[]
            {
                new Claim("Reauth", "true"),
                new Claim("ReauthTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
            }
            .Concat(context.User.Claims)
            .ToArray();

        var scheme = AuthEndpointsConstants.ReAuthScheme;
        var identity = new ClaimsIdentity(claims, scheme);
        await context.SignInAsync(scheme, new ClaimsPrincipal(identity), authProps);

        var reauthToken = tokenService.CreateToken(claims);
        return TypedResults.Ok(new ConfirmIdentityResponse { ReauthToken = reauthToken });
    }
}
