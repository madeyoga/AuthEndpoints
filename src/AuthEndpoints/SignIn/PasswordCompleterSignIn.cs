using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.SignIn;

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
            PasswordHashTiming<TUser>.VerifyUnknownUser(userManager.PasswordHasher, login.Password);
            return InvalidCredentials();
        }

        var password = await signInManager.CheckPasswordSignInAsync(user, login.Password, lockoutOnFailure: true);
        if (!password.Succeeded)
        {
            return InvalidCredentials();
        }

        return await FinishAsync(
            httpContext,
            signInManager,
            userManager,
            user,
            login.TwoFactorCode,
            login.TwoFactorRecoveryCode,
            useCookies,
            useSessionCookies,
            completerName,
            requiresTwoFactorExtension: false);
    }

    public static async Task<IResult> HandleCreate(SimpleJwtLoginRequest request, HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        if (request is null || string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "The request is missing a required body username or password"
            });
        }

        var services = httpContext.RequestServices;
        var authenticator = services.GetRequiredService<IAuthenticator<TUser>>();
        var authenticationResult = await authenticator.AuthenticateAsync(request.Email, request.Password);
        if (authenticationResult.User is null)
        {
            return InvalidCredentials();
        }

        var userManager = services.GetRequiredService<UserManager<TUser>>();
        var signInManager = services.GetRequiredService<SignInManager<TUser>>();
        return await FinishAsync(
            httpContext,
            signInManager,
            userManager,
            authenticationResult.User,
            request.TwoFactorCode,
            request.TwoFactorRecoveryCode,
            useCookies: null,
            useSessionCookies: null,
            SignInCompleters.Jwt,
            requiresTwoFactorExtension: true);
    }

    private static async Task<IResult> FinishAsync(
        HttpContext httpContext,
        SignInManager<TUser> signInManager,
        UserManager<TUser> userManager,
        TUser user,
        string? twoFactorCode,
        string? twoFactorRecoveryCode,
        bool? useCookies,
        bool? useSessionCookies,
        string completerName,
        bool requiresTwoFactorExtension)
    {
        var cookieScheme = UsesApplicationCookie(completerName, useCookies, useSessionCookies);
        var usedTwoFactor = false;
        var rememberClient = false;
        if (await signInManager.IsTwoFactorEnabledAsync(user))
        {
            var remembered = cookieScheme && await signInManager.IsTwoFactorClientRememberedAsync(user);
            if (!remembered)
            {
                if (!string.IsNullOrEmpty(twoFactorCode))
                {
                    var valid = await userManager.VerifyTwoFactorTokenAsync(
                        user,
                        userManager.Options.Tokens.AuthenticatorTokenProvider,
                        twoFactorCode);
                    if (!valid)
                    {
                        await RecordAccessFailedAsync(userManager, user);
                        return InvalidCredentials();
                    }

                    await ResetAccessFailedAsync(userManager, user);
                    usedTwoFactor = true;
                    rememberClient = cookieScheme && IsPersistent(completerName, useCookies, useSessionCookies);
                }
                else if (!string.IsNullOrEmpty(twoFactorRecoveryCode))
                {
                    var redeemed = await userManager.RedeemTwoFactorRecoveryCodeAsync(user, twoFactorRecoveryCode);
                    if (!redeemed.Succeeded)
                    {
                        // SignInManager.TwoFactorRecoveryCodeSignInAsync does not call AccessFailedAsync on a bad code.
                        await RecordAccessFailedAsync(userManager, user);
                        return InvalidCredentials();
                    }

                    await ResetAccessFailedAsync(userManager, user);
                    usedTwoFactor = true;
                }
                else
                {
                    return RequiresTwoFactor(requiresTwoFactorExtension);
                }
            }
        }

        var completer = httpContext.RequestServices.GetRequiredKeyedService<ISignInCompleter<TUser>>(completerName);
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

    private static async Task RecordAccessFailedAsync(UserManager<TUser> userManager, TUser user)
    {
        if (userManager.SupportsUserLockout)
        {
            await userManager.AccessFailedAsync(user);
        }
    }

    private static async Task ResetAccessFailedAsync(UserManager<TUser> userManager, TUser user)
    {
        if (userManager.SupportsUserLockout)
        {
            await userManager.ResetAccessFailedCountAsync(user);
        }
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

    private static IResult RequiresTwoFactor(bool includeExtension)
    {
        if (!includeExtension)
        {
            return TypedResults.Problem(
                title: "RequiresTwoFactor",
                detail: "Two-factor authentication is required.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return TypedResults.Problem(
            title: "RequiresTwoFactor",
            detail: "Two-factor authentication is required.",
            statusCode: StatusCodes.Status401Unauthorized,
            extensions: new Dictionary<string, object?>
            {
                ["requiresTwoFactor"] = true,
            });
    }

    private static IResult InvalidCredentials()
    {
        return TypedResults.Problem(
            title: "Unauthorized",
            detail: "Invalid credentials.",
            statusCode: StatusCodes.Status401Unauthorized);
    }
}
