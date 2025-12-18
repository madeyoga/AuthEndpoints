// Portions of this file are derived from aspnetcore
// https://github.com/dotnet/aspnetcore/blob/main/src/Identity/Core/src/IdentityApiEndpointRouteBuilderExtensions.cs

using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Identity;

public class IdentityApiEndpoints<TUser>
    where TUser : class, new()
{
    private static readonly EmailAddressAttribute _emailAddressAttribute = new();
    public static string? ConfirmEmailEndpointName { get; set; }

    public static async Task<Results<Ok, ValidationProblem>> Register([FromBody] RegisterRequest registration, HttpContext context, [FromServices] IServiceProvider sp)
    {
        var userManager = sp.GetRequiredService<UserManager<TUser>>();

        if (!userManager.SupportsUserEmail)
        {
            throw new NotSupportedException($"{nameof(IdentityApiEndpoints<TUser>)} requires a user store with email support.");
        }

        var userStore = sp.GetRequiredService<IUserStore<TUser>>();
        var emailStore = (IUserEmailStore<TUser>)userStore;
        var email = registration.Email;

        if (string.IsNullOrEmpty(email) || !_emailAddressAttribute.IsValid(email))
        {
            return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(email)));
        }

        var user = new TUser();
        await userStore.SetUserNameAsync(user, email, CancellationToken.None);
        await emailStore.SetEmailAsync(user, email, CancellationToken.None);
        var result = await userManager.CreateAsync(user, registration.Password);

        if (!result.Succeeded)
        {
            return CreateValidationProblem(result);
        }

        await SendConfirmationEmailAsync(user, userManager, context, email);
        return TypedResults.Ok();
    }

    public static async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>> Login
        ([FromBody] LoginRequest login, [FromQuery] bool? useCookies, [FromQuery] bool? useSessionCookies, [FromServices] IServiceProvider sp)
    {
        var signInManager = sp.GetRequiredService<SignInManager<TUser>>();

        var useCookieScheme = (useCookies == true) || (useSessionCookies == true);
        var isPersistent = (useCookies == true) && (useSessionCookies != true);
        signInManager.AuthenticationScheme = useCookieScheme ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;

        var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent, lockoutOnFailure: true);

        if (result.RequiresTwoFactor)
        {
            if (!string.IsNullOrEmpty(login.TwoFactorCode))
            {
                result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, isPersistent, rememberClient: isPersistent);
            }
            else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
            {
                result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
            }
        }

        if (!result.Succeeded)
        {
            return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
        }

        // The signInManager already produced the needed response in the form of a cookie or bearer token.
        return TypedResults.Empty;
    }

    public static async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>> LoginCookie
        ([FromBody] LoginRequest login, [FromQuery] bool? useSessionCookies, [FromServices] IServiceProvider sp)
    {
        var signInManager = sp.GetRequiredService<SignInManager<TUser>>();

        var isPersistent = useSessionCookies == false;
        signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;

        var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent, lockoutOnFailure: true);

        if (result.RequiresTwoFactor)
        {
            if (!string.IsNullOrEmpty(login.TwoFactorCode))
            {
                result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, isPersistent, rememberClient: isPersistent);
            }
            else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
            {
                result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
            }
        }

        if (!result.Succeeded)
        {
            return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
        }

        // The signInManager already produced the needed response in the form of a cookie or bearer token.
        return TypedResults.Empty;
    }

    public static async Task<Results<Ok<AccessTokenResponse>, UnauthorizedHttpResult, SignInHttpResult, ChallengeHttpResult>> Refresh
        ([FromBody] RefreshRequest refreshRequest, [FromServices] IServiceProvider sp)
    {
        var bearerTokenOptions = sp.GetRequiredService<IOptionsMonitor<BearerTokenOptions>>();
        var timeProvider = sp.GetRequiredService<TimeProvider>();
        var signInManager = sp.GetRequiredService<SignInManager<TUser>>();
        var refreshTokenProtector = bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
        var refreshTicket = refreshTokenProtector.Unprotect(refreshRequest.RefreshToken);

        // Reject the /refresh attempt with a 401 if the token expired or the security stamp validation fails
        if (refreshTicket?.Properties?.ExpiresUtc is not { } expiresUtc ||
            timeProvider.GetUtcNow() >= expiresUtc ||
            await signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not TUser user)
        {
            return TypedResults.Challenge();
        }

        var newPrincipal = await signInManager.CreateUserPrincipalAsync(user);
        return TypedResults.SignIn(newPrincipal, authenticationScheme: IdentityConstants.BearerScheme);
    }

    /// <summary>
    /// When <c>useCookies=true</c> is passed to the /login endpoint, tokens are stored
    /// in cookies instead of being returned to the client. This logout endpoint clears those cookies
    /// by signing out from Identity authentication schemes 
    /// <see cref="IdentityConstants.ApplicationScheme"/>
    /// </summary>
    public static IResult Logout()
    {
        return Results.SignOut(authenticationSchemes:
        [
            IdentityConstants.ApplicationScheme,
            IdentityConstants.ExternalScheme,
            IdentityConstants.TwoFactorUserIdScheme,
            IdentityConstants.TwoFactorRememberMeScheme,
            AuthEndpointsConstants.ReAuthScheme
        ]);
    }

    /// <summary>
    /// Generates and stores an anti-forgery (CSRF) token for the current HTTP request and returns it.
    /// </summary>
    /// <returns>
    /// Clients can call this endpoint to obtain csrf token to include in subsequent unsafe requests (POST/PUT/PATCH) for CSRF protection.
    /// </returns>
    public static IResult GetAntiforgeryToken(IAntiforgery forgeryService, HttpContext context)
    {
        var tokens = forgeryService.GetAndStoreTokens(context);

        return Results.Ok(new { CsrfToken = tokens.RequestToken });
    }

    public static async Task<Results<ContentHttpResult, UnauthorizedHttpResult>> ConfirmEmail(
        [FromQuery] string userId,
        [FromQuery] string code,
        [FromQuery] string? changedEmail,
        [FromServices] IServiceProvider sp)
    {
        var userManager = sp.GetRequiredService<UserManager<TUser>>();
        if (await userManager.FindByIdAsync(userId) is not { } user)
        {
            // We could respond with a 404 instead of a 401 like Identity UI, but that feels like unnecessary information.
            return TypedResults.Unauthorized();
        }

        try
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        }
        catch (FormatException)
        {
            return TypedResults.Unauthorized();
        }

        IdentityResult result;

        if (string.IsNullOrEmpty(changedEmail))
        {
            result = await userManager.ConfirmEmailAsync(user, code);
        }
        else
        {
            // As with Identity UI, email and user name are one and the same. So when we update the email,
            // we need to update the user name.
            result = await userManager.ChangeEmailAsync(user, changedEmail, code);

            if (result.Succeeded)
            {
                result = await userManager.SetUserNameAsync(user, changedEmail);
            }
        }

        if (!result.Succeeded)
        {
            return TypedResults.Unauthorized();
        }

        return TypedResults.Text("Thank you for confirming your email.");
    }

    public static async Task<Ok> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest resendRequest, HttpContext context, [FromServices] IServiceProvider sp)
    {
        var userManager = sp.GetRequiredService<UserManager<TUser>>();
        if (await userManager.FindByEmailAsync(resendRequest.Email) is not { } user)
        {
            return TypedResults.Ok();
        }

        await SendConfirmationEmailAsync(user, userManager, context, resendRequest.Email);
        return TypedResults.Ok();
    }

    public static async Task<Results<UnauthorizedHttpResult, Ok>> ConfirmIdentity([FromBody] ConfirmIdentityRequest request, UserManager<TUser> userManager, SignInManager<TUser> signInManager, HttpContext context)
    {
        var user = await userManager.GetUserAsync(context.User);

        if (user == null)
        {
            return TypedResults.Unauthorized();
        }

        var valid = false;
        var IsTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user);

        if (IsTwoFactorEnabled && !string.IsNullOrEmpty(request.TwoFactorCode))
        {
            var result = await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, request.TwoFactorCode);
            valid = result;
        }
        else if (!string.IsNullOrEmpty(request.Password))
        {
            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            valid = result.Succeeded;
        }

        if (!valid)
            return TypedResults.Unauthorized();

        var authProps = new AuthenticationProperties()
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

        return TypedResults.Ok();
    }

    public static async Task<Results<Ok, ValidationProblem>> ForgotPassword
        ([FromBody] ForgotPasswordRequest resetRequest, [FromServices] IServiceProvider sp)
    {
        var userManager = sp.GetRequiredService<UserManager<TUser>>();
        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user is not null && await userManager.IsEmailConfirmedAsync(user))
        {
            var code = await userManager.GeneratePasswordResetTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var emailSender = sp.GetRequiredService<IEmailSender<TUser>>();
            await emailSender.SendPasswordResetCodeAsync(user, resetRequest.Email, HtmlEncoder.Default.Encode(code));
        }

        // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we would have
        // returned a 400 for an invalid code given a valid user email.
        return TypedResults.Ok();
    }

    public static async Task<Results<Ok, ValidationProblem>> ResetPassword
        ([FromBody] ResetPasswordRequest resetRequest, [FromServices] IServiceProvider sp)
    {
        var userManager = sp.GetRequiredService<UserManager<TUser>>();

        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user is null || !await userManager.IsEmailConfirmedAsync(user))
        {
            // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we would have
            // returned a 400 for an invalid code given a valid user email.
            return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken()));
        }

        IdentityResult result;
        try
        {
            var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetRequest.ResetCode));
            result = await userManager.ResetPasswordAsync(user, code, resetRequest.NewPassword);
        }
        catch (FormatException)
        {
            result = IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken());
        }

        if (!result.Succeeded)
        {
            return CreateValidationProblem(result);
        }

        return TypedResults.Ok();
    }

    public static async Task<IResult> TwoFactorStatus(UserManager<TUser> userManager, ClaimsPrincipal user)
    {
        var currentUser = await userManager.GetUserAsync(user);
        if (currentUser is null)
            return Results.Unauthorized();

        return Results.Ok(new
        {
            IsTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(currentUser)
        });
    }

    public static async Task<Results<Ok<TwoFactorResponse>, ValidationProblem, NotFound>> ManageTwoFactor(ClaimsPrincipal claimsPrincipal, [FromBody] TwoFactorRequest tfaRequest, [FromServices] IServiceProvider sp)
    {
        var signInManager = sp.GetRequiredService<SignInManager<TUser>>();
        var userManager = signInManager.UserManager;
        if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
        {
            return TypedResults.NotFound();
        }

        if (tfaRequest.Enable == true)
        {
            if (tfaRequest.ResetSharedKey)
            {
                return CreateValidationProblem("CannotResetSharedKeyAndEnable",
                    "Resetting the 2fa shared key must disable 2fa until a 2fa token based on the new shared key is validated.");
            }

            if (string.IsNullOrEmpty(tfaRequest.TwoFactorCode))
            {
                return CreateValidationProblem("RequiresTwoFactor",
                    "No 2fa token was provided by the request. A valid 2fa token is required to enable 2fa.");
            }

            if (!await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, tfaRequest.TwoFactorCode))
            {
                return CreateValidationProblem("InvalidTwoFactorCode",
                    "The 2fa token provided by the request was invalid. A valid 2fa token is required to enable 2fa.");
            }

            await userManager.SetTwoFactorEnabledAsync(user, true);
        }
        else if (tfaRequest.Enable == false || tfaRequest.ResetSharedKey)
        {
            await userManager.SetTwoFactorEnabledAsync(user, false);
        }

        if (tfaRequest.ResetSharedKey)
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
        }

        string[]? recoveryCodes = null;
        if (tfaRequest.ResetRecoveryCodes || (tfaRequest.Enable == true && await userManager.CountRecoveryCodesAsync(user) == 0))
        {
            var recoveryCodesEnumerable = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            recoveryCodes = recoveryCodesEnumerable?.ToArray();
        }

        if (tfaRequest.ForgetMachine)
        {
            await signInManager.ForgetTwoFactorClientAsync();
        }

        var key = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            key = await userManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(key))
            {
                throw new NotSupportedException("The user manager must produce an authenticator key after reset.");
            }
        }

        return TypedResults.Ok(new TwoFactorResponse
        {
            SharedKey = key,
            RecoveryCodes = recoveryCodes,
            RecoveryCodesLeft = recoveryCodes?.Length ?? await userManager.CountRecoveryCodesAsync(user),
            IsTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user),
            IsMachineRemembered = await signInManager.IsTwoFactorClientRememberedAsync(user),
        });
    }

    public static async Task<Results<Ok<InfoResponse>, ValidationProblem, NotFound>> ManageInfoGet
        (ClaimsPrincipal claimsPrincipal, [FromServices] IServiceProvider sp)
    {
        var userManager = sp.GetRequiredService<UserManager<TUser>>();
        if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
        {
            return TypedResults.NotFound();
        }

        return TypedResults.Ok(new InfoResponse()
        {
            Email = await userManager.GetEmailAsync(user) ?? throw new NotSupportedException("Users must have an email."),
            IsEmailConfirmed = await userManager.IsEmailConfirmedAsync(user),
        });
    }

    public static async Task<Results<Ok<InfoResponse>, ValidationProblem, NotFound>> ManageInfoPost
        (ClaimsPrincipal claimsPrincipal, [FromBody] InfoRequest infoRequest, HttpContext context, [FromServices] IServiceProvider sp)
    {
        var userManager = sp.GetRequiredService<UserManager<TUser>>();
        if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
        {
            return TypedResults.NotFound();
        }

        if (!string.IsNullOrEmpty(infoRequest.NewEmail) && !_emailAddressAttribute.IsValid(infoRequest.NewEmail))
        {
            return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(infoRequest.NewEmail)));
        }

        if (!string.IsNullOrEmpty(infoRequest.NewPassword))
        {
            if (string.IsNullOrEmpty(infoRequest.OldPassword))
            {
                return CreateValidationProblem("OldPasswordRequired",
                    "The old password is required to set a new password. If the old password is forgotten, use /resetPassword.");
            }

            var changePasswordResult = await userManager.ChangePasswordAsync(user, infoRequest.OldPassword, infoRequest.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                return CreateValidationProblem(changePasswordResult);
            }
        }

        if (!string.IsNullOrEmpty(infoRequest.NewEmail))
        {
            var email = await userManager.GetEmailAsync(user);

            if (email != infoRequest.NewEmail)
            {
                await SendConfirmationEmailAsync(user, userManager, context, infoRequest.NewEmail, isChange: true);
            }
        }

        return TypedResults.Ok(new InfoResponse()
        {
            Email = await userManager.GetEmailAsync(user) ?? throw new NotSupportedException("Users must have an email."),
            IsEmailConfirmed = await userManager.IsEmailConfirmedAsync(user),
        });
    }

    private static async Task SendConfirmationEmailAsync(
        TUser user,
        UserManager<TUser> userManager,
        HttpContext context,
        string email,
        bool isChange = false)
    {
        if (ConfirmEmailEndpointName is null)
        {
            throw new NotSupportedException("No email confirmation endpoint was registered!");
        }

        var emailSender = context.RequestServices.GetRequiredService<IEmailSender<TUser>>();
        var linkGenerator = context.RequestServices.GetRequiredService<LinkGenerator>();

        var code = isChange
            ? await userManager.GenerateChangeEmailTokenAsync(user, email)
            : await userManager.GenerateEmailConfirmationTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var userId = await userManager.GetUserIdAsync(user);
        var routeValues = new RouteValueDictionary()
        {
            ["userId"] = userId,
            ["code"] = code,
        };

        if (isChange)
        {
            // This is validated by the /confirmEmail endpoint on change.
            routeValues.Add("changedEmail", email);
        }

        var confirmEmailUrl = linkGenerator.GetUriByName(context, ConfirmEmailEndpointName, routeValues)
            ?? throw new NotSupportedException($"Could not find endpoint named '{ConfirmEmailEndpointName}'.");

        await emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));
    }

    private static ValidationProblem CreateValidationProblem(string errorCode, string errorDescription) =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]> {
            { errorCode, [errorDescription] }
        });

    private static ValidationProblem CreateValidationProblem(IdentityResult result)
    {
        // We expect a single error code and description in the normal case.
        // This could be golfed with GroupBy and ToDictionary, but perf! :P
        Debug.Assert(!result.Succeeded);
        var errorDictionary = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newDescriptions;

            if (errorDictionary.TryGetValue(error.Code, out var descriptions))
            {
                newDescriptions = new string[descriptions.Length + 1];
                Array.Copy(descriptions, newDescriptions, descriptions.Length);
                newDescriptions[descriptions.Length] = error.Description;
            }
            else
            {
                newDescriptions = [error.Description];
            }

            errorDictionary[error.Code] = newDescriptions;
        }

        return TypedResults.ValidationProblem(errorDictionary);
    }
}
