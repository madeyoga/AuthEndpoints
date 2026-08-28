using System.Buffers.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Passkey;

/// <summary>
/// Completes passkey sign-in with Identity application cookie or bearer tokens
/// (same <c>useCookies</c> / <c>useSessionCookies</c> rules as Identity login).
/// </summary>
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

        var isPersistent = ConfigureAuthenticationScheme(
            _signInManager,
            context.UseCookies,
            context.UseSessionCookies);

        await _signInManager.SignInAsync(user, isPersistent);

        if (context.Kind == PasskeySignInKind.Register && context.CredentialId is { Length: > 0 })
        {
            return TypedResults.Ok(new PasskeyCredentialResponse(
                Base64Url.EncodeToString(context.CredentialId)));
        }

        // SignInManager already produced the cookie or Identity bearer token response.
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

    /// <summary>
    /// Matches IdentityApiEndpoints.Login: cookie flags select ApplicationScheme; otherwise BearerScheme.
    /// </summary>
    private static bool ConfigureAuthenticationScheme(
        SignInManager<TUser> signInManager,
        bool? useCookies,
        bool? useSessionCookies)
    {
        var useCookieScheme = useCookies == true || useSessionCookies == true;
        var isPersistent = useCookies == true && useSessionCookies != true;
        signInManager.AuthenticationScheme = useCookieScheme
            ? IdentityConstants.ApplicationScheme
            : IdentityConstants.BearerScheme;
        return isPersistent;
    }
}
