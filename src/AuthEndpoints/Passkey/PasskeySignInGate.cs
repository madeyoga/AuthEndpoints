using System.Buffers.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Passkey;

internal static class PasskeySignInGate
{
    public static async Task<bool> CanCompleteAsync<TUser>(SignInManager<TUser> signInManager, TUser user)
        where TUser : class
    {
        return !await signInManager.UserManager.IsLockedOutAsync(user)
            && await signInManager.CanSignInAsync(user);
    }

    public static IResult Denied(PasskeySignInKind kind, byte[]? credentialId)
    {
        if (kind == PasskeySignInKind.Register)
        {
            if (credentialId is { Length: > 0 })
            {
                return TypedResults.Ok(new PasskeyCredentialResponse(
                    Base64Url.EncodeToString(credentialId)));
            }

            return TypedResults.Ok();
        }

        return TypedResults.Problem(
            title: "Unauthorized",
            detail: "Invalid credentials.",
            statusCode: StatusCodes.Status401Unauthorized);
    }

    public static async Task<IResult> CompleteIfAllowedAsync<TUser>(
        SignInManager<TUser> signInManager,
        IPasskeySignInCompleter<TUser> completer,
        HttpContext httpContext,
        TUser user,
        PasskeySignInCompletionContext context,
        CancellationToken cancellationToken)
        where TUser : class
    {
        if (!await CanCompleteAsync(signInManager, user))
        {
            return Denied(context.Kind, context.CredentialId);
        }

        return await completer.CompleteAsync(httpContext, user, context, cancellationToken);
    }
}
