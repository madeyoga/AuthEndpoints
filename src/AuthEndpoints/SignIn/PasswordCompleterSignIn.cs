using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.SignIn;

/// <summary>
/// Password login used when a map selects a completer or <see cref="SignInCompletionOptions.Default"/> is set.
/// The 3.x <c>PasswordLoginMode</c> handlers stay on <c>PasswordSignInAsync</c>.
/// </summary>
internal static class PasswordCompleterSignIn<TUser>
    where TUser : class
{
    public static async Task<IResult> Handle(
        LoginRequest login,
        bool? useCookies,
        bool? useSessionCookies,
        HttpContext httpContext,
        string completerName)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(completerName);

        if (login is null || string.IsNullOrEmpty(login.Email))
        {
            return InvalidCredentials();
        }

        var services = httpContext.RequestServices;
        var userManager = services.GetRequiredService<UserManager<TUser>>();
        var signInManager = services.GetRequiredService<SignInManager<TUser>>();
        var user = await userManager.FindByNameAsync(login.Email);
        if (user is null)
        {
            return InvalidCredentials();
        }

        var password = await signInManager.CheckPasswordSignInAsync(user, login.Password, lockoutOnFailure: true);
        if (!password.Succeeded)
        {
            return InvalidCredentials();
        }

        var cookieScheme = UsesApplicationCookie(completerName, useCookies, useSessionCookies);
        var usedTwoFactor = false;
        var rememberClient = false;
        if (await signInManager.IsTwoFactorEnabledAsync(user))
        {
            var remembered = cookieScheme && await signInManager.IsTwoFactorClientRememberedAsync(user);
            if (!remembered)
            {
                if (!string.IsNullOrEmpty(login.TwoFactorCode))
                {
                    var valid = await userManager.VerifyTwoFactorTokenAsync(
                        user,
                        userManager.Options.Tokens.AuthenticatorTokenProvider,
                        login.TwoFactorCode);
                    if (!valid)
                    {
                        if (userManager.SupportsUserLockout)
                        {
                            await userManager.AccessFailedAsync(user);
                        }

                        return InvalidCredentials();
                    }

                    if (userManager.SupportsUserLockout)
                    {
                        await userManager.ResetAccessFailedCountAsync(user);
                    }

                    usedTwoFactor = true;
                    rememberClient = cookieScheme && IsPersistent(completerName, useCookies, useSessionCookies);
                }
                else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
                {
                    var redeemed = await userManager.RedeemTwoFactorRecoveryCodeAsync(user, login.TwoFactorRecoveryCode);
                    if (!redeemed.Succeeded)
                    {
                        return InvalidCredentials();
                    }

                    if (userManager.SupportsUserLockout)
                    {
                        await userManager.ResetAccessFailedCountAsync(user);
                    }

                    usedTwoFactor = true;
                }
                else
                {
                    return TypedResults.Problem(
                        title: "RequiresTwoFactor",
                        detail: "Two-factor authentication is required.",
                        statusCode: StatusCodes.Status401Unauthorized);
                }
            }
        }

        var completer = services.GetRequiredKeyedService<ISignInCompleter<TUser>>(completerName);
        return await completer.CompleteAsync(
            httpContext,
            user,
            new SignInCompletionContext
            {
                Method = SignInMethod.Password,
                UseCookies = useCookies,
                UseSessionCookies = useSessionCookies,
                UsedTwoFactor = usedTwoFactor,
                RememberTwoFactorClient = rememberClient,
            },
            httpContext.RequestAborted);
    }

    private static bool UsesApplicationCookie(string completerName, bool? useCookies, bool? useSessionCookies)
    {
        if (string.Equals(completerName, SignInCompleters.Cookie, StringComparison.Ordinal))
        {
            return true;
        }

        if (string.Equals(completerName, SignInCompleters.IdentityBearer, StringComparison.Ordinal))
        {
            return useCookies == true || useSessionCookies == true;
        }

        return false;
    }

    private static bool IsPersistent(string completerName, bool? useCookies, bool? useSessionCookies)
    {
        if (string.Equals(completerName, SignInCompleters.Cookie, StringComparison.Ordinal))
        {
            return useSessionCookies == false;
        }

        return useCookies == true && useSessionCookies != true;
    }

    private static IResult InvalidCredentials()
    {
        return TypedResults.Problem(
            title: "Unauthorized",
            detail: "Invalid credentials.",
            statusCode: StatusCodes.Status401Unauthorized);
    }
}
