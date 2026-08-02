using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.Passkey;

/// <summary>
/// Completes sign-in after a passkey register or login ceremony has been validated.
/// Default implementation issues Identity cookie or bearer tokens; replace for Simple JWT.
/// </summary>
public interface IPasskeySignInCompleter<TUser>
    where TUser : class
{
    Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        PasskeySignInCompletionContext context,
        CancellationToken cancellationToken = default);
}
