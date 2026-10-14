namespace AuthEndpoints.Identity;

/// <summary>
/// Sends the notice that an authentication method changed, or that registration was attempted for an existing account.
/// Queue the message and return. Sending it inline over SMTP makes a known address slower than an unknown one.
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

    /// <summary>
    /// Tells <paramref name="email"/> that someone tried to register an account with that address.
    /// The attempted password is not included. <c>POST /register</c> calls this when the email is already registered
    /// and the password meets the password rules, then returns the same empty 200 as a new account.
    /// </summary>
    Task SendRegistrationAttemptedAsync(TUser user, string email, CancellationToken cancellationToken = default);
}
