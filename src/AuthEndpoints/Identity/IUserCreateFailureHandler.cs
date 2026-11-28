namespace AuthEndpoints.Identity;

/// <summary>
/// Recovers when <c>UserManager&lt;TUser&gt;.CreateAsync</c> throws while AuthEndpoints creates an account itself
/// (email-code sign-up). Without a handler, the exception propagates.
/// </summary>
/// <remarks>
/// The usual cause is a race: another request created an account with the same email between the lookup and the insert,
/// and the store's unique index refused the second insert.
/// </remarks>
public interface IUserCreateFailureHandler<TUser>
    where TUser : class
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="exception"/> means the store refused the insert. AuthEndpoints
    /// then looks the account up by email: an existing account continues sign-in, and otherwise sign-up fails with
    /// <c>401</c>. Return <see langword="false"/> to let the exception propagate.
    /// Before it returns <see langword="true"/>, the handler must discard whatever the store still holds for
    /// <paramref name="user"/>, so a later save in the same request does not try the insert again.
    /// </summary>
    bool TryRecover(TUser user, Exception exception);
}
