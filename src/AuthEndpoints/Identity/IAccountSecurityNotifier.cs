namespace AuthEndpoints.Identity;

/// <summary>
/// Receives each account security event: a sign-in method changed, or someone tried to register an existing address.
/// One method takes every kind, so a kind added in a later version reaches existing implementations.
/// <see cref="LoggingAccountSecurityNotifier{TUser}"/> is the default and only logs.
/// Register an implementation to deliver the notice, for example by email.
/// </summary>
/// <remarks>
/// Queue the message and return. Sending it inline over SMTP makes a known address slower than an unknown one,
/// which reveals that the address has an account. Handle kinds you do not recognize, for example by ignoring them.
/// </remarks>
public interface IAccountSecurityNotifier<TUser>
    where TUser : class
{
    /// <summary>Handles one account security event. Throwing fails the request that raised it.</summary>
    Task NotifyAsync(AccountSecurityEvent<TUser> securityEvent, CancellationToken cancellationToken = default);
}

/// <summary>One account security event.</summary>
/// <param name="Kind">What happened.</param>
/// <param name="User">The account it happened to.</param>
/// <param name="Email">
/// The address to notify: the account's email, or null when the account has none (for example one that signs in by
/// user name). For <see cref="AccountSecurityEventKind.RegistrationAttempted"/> it is never null.
/// </param>
public sealed record AccountSecurityEvent<TUser>(AccountSecurityEventKind Kind, TUser User, string? Email)
    where TUser : class;

/// <summary>The kinds of <see cref="AccountSecurityEvent{TUser}"/>. Later versions may add kinds.</summary>
public enum AccountSecurityEventKind
{
    /// <summary>A password was added to an account that had none (<c>POST /manage/password</c>). The password is not included.</summary>
    PasswordSet = 1,

    /// <summary>The account's password was removed (<c>DELETE /manage/password</c>).</summary>
    PasswordRemoved = 2,

    /// <summary>
    /// Someone tried to register with an address that already has an account. <c>POST /register</c> raises it when the
    /// password meets the password rules, then returns the same empty 200 as for a new account.
    /// The attempted password is not included.
    /// </summary>
    RegistrationAttempted = 3,
}
