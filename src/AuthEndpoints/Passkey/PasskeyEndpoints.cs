using System.Buffers.Text;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.Passkey;

public static class PasskeyEndpoints<TUser>
    where TUser : class, new()
{
    private static readonly EmailAddressAttribute EmailAddressAttribute = new();

    public static async Task<Results<ContentHttpResult, NotFound, ValidationProblem, ProblemHttpResult>> CreationOptions(
        HttpContext context,
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return TypedResults.NotFound();
        }

        var userId = await userManager.GetUserIdAsync(user);
        var userName = await userManager.GetUserNameAsync(user) ?? "User";

        var optionsJson = await signInManager.MakePasskeyCreationOptionsAsync(new()
        {
            Id = userId,
            Name = userName,
            DisplayName = userName
        });

        return TypedResults.Content(optionsJson, contentType: "application/json");
    }

    public static async Task<ContentHttpResult> RequestOptions(
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        [FromQuery] string? username)
    {
        var user = string.IsNullOrEmpty(username) ? null : await userManager.FindByNameAsync(username);
        var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(user);
        return TypedResults.Content(optionsJson, contentType: "application/json");
    }

    public static async Task<Results<Ok<PasskeyCredentialResponse>, NotFound, ProblemHttpResult>> AddPasskey(
        [FromBody] PasskeyVerifyAndStoreRequest request,
        HttpContext context,
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return TypedResults.NotFound();
        }

        if (string.IsNullOrEmpty(request.CredentialJson))
        {
            return TypedResults.Problem(
                detail: "The browser did not provide a passkey.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var attestationResult = await signInManager.PerformPasskeyAttestationAsync(request.CredentialJson);
        if (!attestationResult.Succeeded)
        {
            return TypedResults.Problem(
                detail: $"Could not add the passkey: {attestationResult.Failure.Message}",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var addPasskeyResult = await userManager.AddOrUpdatePasskeyAsync(user, attestationResult.Passkey);
        if (!addPasskeyResult.Succeeded)
        {
            return TypedResults.Problem(
                detail: "The passkey could not be added to your account.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return TypedResults.Ok(new PasskeyCredentialResponse(
            Base64Url.EncodeToString(attestationResult.Passkey.CredentialId)));
    }

    public static async Task<Results<Ok<PasskeyListResponse>, NotFound>> ListPasskeys(
        ClaimsPrincipal principal,
        UserManager<TUser> userManager)
    {
        var user = await userManager.GetUserAsync(principal);
        if (user is null)
        {
            return TypedResults.NotFound();
        }

        var passkeys = await userManager.GetPasskeysAsync(user);
        var response = passkeys.Select(passkey => new PasskeyCredentialResponse(
            Base64Url.EncodeToString(passkey.CredentialId),
            passkey.Name)).ToList();

        return TypedResults.Ok(new PasskeyListResponse(response));
    }

    public static async Task<Results<Ok, NotFound, ProblemHttpResult>> RenamePasskey(
        [FromBody] PasskeyRenameRequest request,
        HttpContext context,
        UserManager<TUser> userManager)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return TypedResults.NotFound();
        }

        byte[] credentialId;
        try
        {
            credentialId = Base64Url.DecodeFromChars(request.Id);
        }
        catch (FormatException)
        {
            return TypedResults.Problem(
                detail: "The specified passkey ID had an invalid format.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var passkey = await userManager.GetPasskeyAsync(user, credentialId);
        if (passkey is null)
        {
            return TypedResults.Problem(
                detail: "The specified passkey could not be found.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        passkey.Name = request.NewName;
        var updateResult = await userManager.AddOrUpdatePasskeyAsync(user, passkey);
        if (!updateResult.Succeeded)
        {
            return TypedResults.Problem(
                detail: "The passkey could not be updated.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return TypedResults.Ok();
    }

    public static async Task<Results<Ok, NotFound, ProblemHttpResult>> DeletePasskey(
        string credentialIdUrl,
        HttpContext context,
        UserManager<TUser> userManager)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return TypedResults.NotFound();
        }

        byte[] credentialId;
        try
        {
            credentialId = Base64Url.DecodeFromChars(credentialIdUrl);
        }
        catch (FormatException)
        {
            return TypedResults.Problem(
                detail: "The specified passkey ID had an invalid format.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var result = await userManager.RemovePasskeyAsync(user, credentialId);
        if (!result.Succeeded)
        {
            return TypedResults.Problem(
                detail: "The passkey could not be deleted.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return TypedResults.Ok();
    }

    public static async Task<Results<ContentHttpResult, ValidationProblem, ProblemHttpResult>> RegisterOptions(
        [FromBody] PasskeyRegisterOptionsRequest request,
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager)
    {
        if (!userManager.SupportsUserEmail)
        {
            throw new NotSupportedException($"{nameof(PasskeyEndpoints<TUser>)} requires a user store with email support.");
        }

        var email = request.Email?.Trim();
        if (string.IsNullOrEmpty(email) || !EmailAddressAttribute.IsValid(email))
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]>
            {
                ["Email"] = ["A valid email is required for registration."]
            });
        }

        if (await userManager.FindByEmailAsync(email) is not null)
        {
            return TypedResults.Problem(
                detail: "An account with this email already exists.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var userId = UserIdHelper.CreateUserIdString(typeof(TUser));
        var optionsJson = await signInManager.MakePasskeyCreationOptionsAsync(new()
        {
            Id = userId,
            Name = email,
            DisplayName = email
        });

        return TypedResults.Content(optionsJson, contentType: "application/json");
    }

    public static async Task<Results<Ok<PasskeyCredentialResponse>, ValidationProblem, ProblemHttpResult>> Register(
        [FromBody] PasskeyRegisterRequest request,
        UserManager<TUser> userManager,
        IUserStore<TUser> userStore,
        SignInManager<TUser> signInManager)
    {
        if (!userManager.SupportsUserEmail)
        {
            throw new NotSupportedException($"{nameof(PasskeyEndpoints<TUser>)} requires a user store with email support.");
        }

        if (userStore is not IUserEmailStore<TUser> emailStore)
        {
            throw new NotSupportedException($"{nameof(PasskeyEndpoints<TUser>)} requires IUserEmailStore<TUser>.");
        }

        var email = request.Email?.Trim();
        if (string.IsNullOrEmpty(email) || !EmailAddressAttribute.IsValid(email))
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]>
            {
                ["Email"] = ["A valid email is required for registration."]
            });
        }

        if (string.IsNullOrEmpty(request.CredentialJson))
        {
            return TypedResults.Problem(
                detail: "The browser did not provide a passkey.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (await userManager.FindByEmailAsync(email) is not null)
        {
            return TypedResults.Problem(
                detail: "An account with this email already exists.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var attestationResult = await signInManager.PerformPasskeyAttestationAsync(request.CredentialJson);
        if (!attestationResult.Succeeded)
        {
            return TypedResults.Problem(
                detail: $"Could not add the passkey: {attestationResult.Failure.Message}",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var userEntity = attestationResult.UserEntity;
        var user = await userManager.FindByIdAsync(userEntity.Id);
        if (user is null)
        {
            user = new TUser();
            UserIdHelper.SetUserId(user, userEntity.Id);
            await userStore.SetUserNameAsync(user, email, CancellationToken.None);
            await emailStore.SetEmailAsync(user, email, CancellationToken.None);

            var createUserResult = await userManager.CreateAsync(user);
            if (!createUserResult.Succeeded)
            {
                return TypedResults.Problem(
                    detail: string.Join(" ", createUserResult.Errors.Select(e => e.Description)),
                    statusCode: StatusCodes.Status400BadRequest);
            }
        }

        var addPasskeyResult = await userManager.AddOrUpdatePasskeyAsync(user, attestationResult.Passkey);
        if (!addPasskeyResult.Succeeded)
        {
            return TypedResults.Problem(
                detail: "The passkey could not be added to your account.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Establish cookie session for passwordless signup (JWT hosts can still call /auth/create separately).
        signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
        await signInManager.SignInAsync(user, isPersistent: false);

        return TypedResults.Ok(new PasskeyCredentialResponse(
            Base64Url.EncodeToString(attestationResult.Passkey.CredentialId)));
    }

    public static async Task<Results<Ok, ProblemHttpResult>> Login(
        [FromBody] PasskeyLoginRequest request,
        SignInManager<TUser> signInManager)
    {
        if (string.IsNullOrEmpty(request.CredentialJson))
        {
            return TypedResults.Problem(
                type: "Bad Request",
                title: "Invalid Credential",
                detail: "No credential was submitted by the browser.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var signInResult = await signInManager.PasskeySignInAsync(request.CredentialJson);
        if (!signInResult.Succeeded)
        {
            return TypedResults.Problem(
                type: "Bad Request",
                title: "Invalid Credential",
                detail: "Could not sign in with the provided credential.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return TypedResults.Ok();
    }
}
