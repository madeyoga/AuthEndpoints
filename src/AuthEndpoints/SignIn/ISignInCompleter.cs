using Microsoft.AspNetCore.Http;

namespace AuthEndpoints;

/// <summary>
/// Finishes a successful sign-in. Called only after the method has verified the proof,
/// checked lockout, satisfied two-factor, passed <c>CanSignInAsync</c>, and reset the access-failed count.
/// Never called for a failure.
/// </summary>
public interface ISignInCompleter<TUser>
    where TUser : class
{
    /// <summary>
    /// Produces the sign-in result for an already-accepted proof.
    /// </summary>
    Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default);
}
