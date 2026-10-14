namespace AuthEndpoints.Identity;

/// <summary>
/// Sends the notice that an authentication method changed.
/// <see cref="LoggingAccountSecurityEmailSender{TUser}"/> is the default and only logs.
/// Register an implementation to deliver the message.
/// </summary>
public interface IAccountSecurityEmailSender<TUser>
    where TUser : class
{
    /// <summary>
    /// Tells <paramref name="email"/> that a password was added to the account.
    /// The password is not included.
    /// </summary>
    Task SendPasswordSetAsync(TUser user, string email, CancellationToken cancellationToken = default);
}
