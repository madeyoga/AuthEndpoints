using System.Buffers.Text;
using System.Security.Claims;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Passkey;

public static class PasskeyEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapPasskeyEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var accountGroup = endpoints.MapGroup("");

        accountGroup.MapPost("/passkeyCreationOptions", async (
            HttpContext context,
            [FromServices] UserManager<TUser> userManager,
            [FromServices] SignInManager<TUser> signInManager,
            [FromServices] IAntiforgery antiforgery) =>
        {
            await antiforgery.ValidateRequestAsync(context);

            var user = await userManager.GetUserAsync(context.User);
            if (user is null)
            {
                return Results.NotFound();
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
        })
        .RequireReauth()
        .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
        .EnableAntiforgery();

        accountGroup.MapPost("/passkeyRequestOptions", async (
            HttpContext context,
            [FromServices] UserManager<TUser> userManager,
            [FromServices] SignInManager<TUser> signInManager,
            [FromServices] IAntiforgery antiforgery,
            [FromQuery] string? username) =>
        {
            await antiforgery.ValidateRequestAsync(context);

            var user = string.IsNullOrEmpty(username) ? null : await userManager.FindByNameAsync(username);
            var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(user);
            return TypedResults.Content(optionsJson, contentType: "application/json");
        })
        .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
        .EnableAntiforgery();

        // Register: verify and store passkey
        accountGroup.MapPost("/passkeys", async (
            [FromBody] PasskeyVerifyAndStoreRequest request, 
            HttpContext context, 
            [FromServices] UserManager<TUser> userManager, 
            [FromServices] SignInManager<TUser> signInManager,
            [FromServices] IAntiforgery antiforgery) =>
        {
            await antiforgery.ValidateRequestAsync(context);
            var user = await userManager.GetUserAsync(context.User);

            if (user is null)
            {
                return Results.Problem(
                    detail: "User not found.",
                    statusCode: StatusCodes.Status404NotFound
                );
            }

            if (string.IsNullOrEmpty(request.CredentialJson))
            {
                return Results.Problem(
                    detail: "Error: The browser did not provide a passkey",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            var attestationResult = await signInManager.PerformPasskeyAttestationAsync(request.CredentialJson);
            if (!attestationResult.Succeeded)
            {
                return Results.Problem(
                    detail: $"Error: Could not add the passkey: {attestationResult.Failure.Message}",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            var addPasskeyResult = await userManager.AddOrUpdatePasskeyAsync(user, attestationResult.Passkey);
            if (!addPasskeyResult.Succeeded)
            {
                return Results.Problem(
                    detail: "Error: The passkey could not be added to your account.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            var credentialIdBase64Url = Base64Url.EncodeToString(attestationResult.Passkey.CredentialId);

            return Results.Ok(new
            {
                CredentialId = credentialIdBase64Url
            });
        })
        .RequireAuthorization()
        .RequireReauth()
        .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
        .EnableAntiforgery();

        accountGroup.MapGet("/passkeys", async (ClaimsPrincipal principal, UserManager<TUser> userManager) =>
        {
            var user = await userManager.GetUserAsync(principal);

            if (user is null)
            {
                return Results.NotFound();
            }

            var passkeys = await userManager.GetPasskeysAsync(user);

            var response = passkeys.Select(passkey => new
            {
                DisplayName = passkey.Name,
                CredentialId = Base64Url.EncodeToString(passkey.CredentialId)
            });

            return Results.Ok(new 
            {
                CredentialIdList = response
            });
        }).RequireAuthorization();

        accountGroup.MapPatch("/passkeys", async (
            [FromBody] PasskeyRenameRequest request, 
            HttpContext context, 
            [FromServices] UserManager<TUser> userManager,
            [FromServices] IAntiforgery antiforgery) =>
        {
            await antiforgery.ValidateRequestAsync(context);
            var user = await userManager.GetUserAsync(context.User);

            if (user is null)
            {
                return Results.NotFound();
            }

            byte[] credentialId;

            try
            {
                credentialId = Base64Url.DecodeFromChars(request.Id);
            }
            catch (FormatException)
            {
                return Results.Problem(
                    detail: "Error: The specified passkey ID had an invalid format.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            var passkey = await userManager.GetPasskeyAsync(user, credentialId);

            if (passkey is null)
            {
                return Results.Problem(
                    detail: "Error: The specified passkey could not be found.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            passkey.Name = request.NewName;

            var updateResult = await userManager.AddOrUpdatePasskeyAsync(user, passkey);

            if (!updateResult.Succeeded)
            {
                return Results.Problem(
                    detail: "Error: The passkey could not be updated.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            return Results.Ok();
        }).RequireAuthorization().EnableAntiforgery();

        accountGroup.MapDelete("/passkeys", async (
            string credentialIdUrl, 
            HttpContext context, 
            [FromServices] UserManager<TUser> userManager,
            [FromServices] IAntiforgery antiforgery) =>
        {
            await antiforgery.ValidateRequestAsync(context);
            var user = await userManager.GetUserAsync(context.User);

            if (user is null)
            {
                return Results.NotFound();
            }

            byte[] credentialId;

            try
            {
                credentialId = Base64Url.DecodeFromChars(credentialIdUrl);
            }
            catch (FormatException)
            {
                return Results.BadRequest("Error: The specified passkey ID had an invalid format.");
            }

            var result = await userManager.RemovePasskeyAsync(user, credentialId);

            if (!result.Succeeded)
            {
                return Results.Problem(
                    detail: "Error: The passkey could not be deleted.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            return Results.Ok();
        })
        .RequireReauth()
        .RequireAuthorization()
        .EnableAntiforgery();

        // Create passkey and a passwordless account
        accountGroup.MapPost("/passkeys/register", async (
            [FromBody] PasskeyRegisterRequest request, 
            HttpContext context, 
            [FromServices] UserManager<TUser> userManager, 
            [FromServices] IUserEmailStore<TUser> userEmailStore,
            [FromServices] IUserStore<TUser> userStore,
            [FromServices] SignInManager<TUser> signInManager,
            [FromServices] IAntiforgery antiforgery) =>
        {
            await antiforgery.ValidateRequestAsync(context);

            if (string.IsNullOrWhiteSpace(request.Email))
            {
                return Results.Problem(
                    detail: "Error: An email is required for registration.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            if (string.IsNullOrEmpty(request.CredentialJson))
            {
                return Results.Problem(
                    detail: "Error: The browser did not provide a passkey",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            var attestationResult = await signInManager.PerformPasskeyAttestationAsync(request.CredentialJson);
            if (!attestationResult.Succeeded)
            {
                return Results.Problem(
                    detail: $"Error: Could not add the passkey: {attestationResult.Failure.Message}",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            var userEntity = attestationResult.UserEntity;
            var user = await userManager.FindByIdAsync(userEntity.Id);
            if (user is null)
            {
                user = new TUser();
                await userStore.SetUserNameAsync(user, request.Email, CancellationToken.None);
                await userEmailStore.SetEmailAsync(user, request.Email, CancellationToken.None);
                var createUserResult = await userManager.CreateAsync(user);
                if (!createUserResult.Succeeded)
                {
                    return Results.Problem(
                        detail: "Error: Could not create a new user.",
                        statusCode: StatusCodes.Status400BadRequest
                    );
                }
            }

            var addPasskeyResult = await userManager.AddOrUpdatePasskeyAsync(user, attestationResult.Passkey);
            if (!addPasskeyResult.Succeeded)
            {
                return Results.Problem(
                    detail: "Error: The passkey could not be added to your account.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            var credentialIdBase64Url = Base64Url.EncodeToString(attestationResult.Passkey.CredentialId);

            return Results.Ok(new
            {
                CredentialId = credentialIdBase64Url
            });
        })
        .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
        .EnableAntiforgery();

        accountGroup.MapPost("/passkeys/login", async (
            HttpContext context,
            [FromBody] PasskeyLoginRequest request, 
            SignInManager<TUser> signInManager,
            [FromServices] IAntiforgery antiforgery) =>
        {
            await antiforgery.ValidateRequestAsync(context);

            if (string.IsNullOrEmpty(request.CredentialJson))
            {
                return Results.Problem(
                    type: "Bad Request",
                    title: "Invalid Credential",
                    detail: "Error: No credential was submitted by the browser.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            var signInResult = await signInManager.PasskeySignInAsync(request.CredentialJson);

            if (!signInResult.Succeeded)
            {
                return Results.Problem(
                    type: "Bad Request",
                    title: "Invalid Credential",
                    detail: "Error: Could not sign in with the provided credential.",
                    statusCode: StatusCodes.Status400BadRequest
                );
            }

            return Results.Ok();
        })
        .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
        .EnableAntiforgery();

        return accountGroup;
    }
}

public record PasskeyVerifyAndStoreRequest(string CredentialJson);
public record PasskeyRenameRequest(string Id, string NewName);
public record PasskeyRegisterRequest(string Email, string CredentialJson);
public record PasskeyLoginRequest(string CredentialJson);
