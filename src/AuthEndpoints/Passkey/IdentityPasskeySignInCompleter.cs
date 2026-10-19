using System.Buffers.Text;
using AuthEndpoints.Identity;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Passkey;

/// <summary>
/// Completes passkey sign-in with Identity application cookie or bearer tokens
/// (same <c>useCookies</c> / <c>useSessionCookies</c> rules as Identity login).
/// Cookie register returns <c>credentialId</c>. Bearer register returns the token body
/// <c>SignInAsync</c> already wrote.
/// </summary>
[Obsolete(LegacyCompleterMessages.Obsolete)]
public sealed class IdentityPasskeySignInCompleter<TUser> : IPasskeySignInCompleter<TUser>
    where TUser : class
{
    private readonly SignInManager<TUser> _signInManager;

    public IdentityPasskeySignInCompleter(SignInManager<TUser> signInManager)
    {
        _signInManager = signInManager;
    }

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        PasskeySignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        if (await _signInManager.UserManager.IsLockedOutAsync(user)
            || !await _signInManager.CanSignInAsync(user))
        {
            return Denied(context);
        }

        var isPersistent = SignInScheme.Configure(
            _signInManager,
            context.UseCookies,
            context.UseSessionCookies);

        await _signInManager.SignInAsync(user, isPersistent);

        // Cookie sign-in only sets the application cookie, so register can still write credentialId.
        // Bearer sign-in writes AccessTokenResponse inside SignInAsync. A second body throws
        // "response has already started", so register returns that token response alone.
        if (context.Kind == PasskeySignInKind.Register
            && context.CredentialId is { Length: > 0 }
            && _signInManager.AuthenticationScheme == IdentityConstants.ApplicationScheme)
        {
            return TypedResults.Ok(new PasskeyCredentialResponse(
                Base64Url.EncodeToString(context.CredentialId)));
        }

        return TypedResults.Empty;
    }

    private static IResult Denied(PasskeySignInCompletionContext context)
    {
        // Password register creates the account and does not sign in when the
        // user is not allowed (e.g. RequireConfirmedAccount). Keep that shape.
        if (context.Kind == PasskeySignInKind.Register && context.CredentialId is { Length: > 0 })
        {
            return TypedResults.Ok(new PasskeyCredentialResponse(
                Base64Url.EncodeToString(context.CredentialId)));
        }

        if (context.Kind == PasskeySignInKind.Register)
        {
            return TypedResults.Ok();
        }

        return TypedResults.Problem(
            title: "Unauthorized",
            detail: "Invalid credentials.",
            statusCode: StatusCodes.Status401Unauthorized);
    }
}
