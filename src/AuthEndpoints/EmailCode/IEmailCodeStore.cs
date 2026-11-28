namespace AuthEndpoints.EmailCode;

/// <summary>
/// Reads and writes email-code rows (<see cref="EmailCodeEntry"/>) for email-code sign-in and step-up.
/// AuthEndpoints generates and hashes codes, links and addresses and decides every rule; a store only stores rows.
/// A store never sees a raw code or link token. Addresses arrive hashed (<see cref="EmailCodeEntry.EmailHash"/>), except
/// <see cref="EmailCodeEntry.SignupEmail"/>: a sign-up row keeps the address in plain text, so the magic link can create
/// the account. Protect it like any other stored email address.
/// </summary>
/// <remarks>
/// Each method is one atomic operation. Concurrent calls for the same row must behave as if they ran one after another:
/// for example, of two concurrent <see cref="TryConsumeAsync"/> calls for one row, at most one returns <see langword="true"/>.
/// A store for a database usually implements each method with one conditional statement, or one transaction.
/// Times are UTC.
/// </remarks>
public interface IEmailCodeStore
{
    /// <summary>
    /// Atomically, for the rows with <paramref name="entry"/>'s <see cref="EmailCodeEntry.EmailHash"/> and
    /// <see cref="EmailCodeEntry.Purpose"/>:
    /// <list type="number">
    /// <item>if <see cref="EmailCodeIssueRules.CooldownSince"/> is set and a row was created after it, stores nothing
    /// and returns <see cref="EmailCodeIssueStatus.Cooldown"/>;</item>
    /// <item>deletes the rows that expired before <see cref="EmailCodeIssueRules.DeleteExpiredBefore"/>;</item>
    /// <item>sets <see cref="EmailCodeEntry.SupersededAt"/> to <see cref="EmailCodeLiveness.Now"/> on every live row
    /// (see <see cref="EmailCodeLiveness"/>);</item>
    /// <item>inserts <paramref name="entry"/>.</item>
    /// </list>
    /// Two concurrent calls for one address and purpose must not both pass the cooldown, and must not leave two live rows.
    /// </summary>
    /// <returns>
    /// <see cref="EmailCodeIssueStatus.Conflict"/> when the store could not run the steps atomically, for example a
    /// serialization failure that persisted after the store's own retries. Nothing is stored, and no code is sent.
    /// </returns>
    Task<EmailCodeIssueStatus> IssueAsync(
        EmailCodeEntry entry,
        EmailCodeIssueRules rules,
        CancellationToken cancellationToken);

    /// <summary>
    /// Returns the newest live row (latest <see cref="EmailCodeEntry.CreatedAt"/>, then greatest
    /// <see cref="EmailCodeEntry.Id"/>) for the address and purpose, or <see langword="null"/>.
    /// When <paramref name="userId"/> is set, only rows with that <see cref="EmailCodeEntry.UserId"/> count.
    /// </summary>
    Task<EmailCodeEntry?> FindLiveByEmailAsync(
        string emailHash,
        EmailCodeRowPurpose purpose,
        string? userId,
        EmailCodeLiveness liveness,
        CancellationToken cancellationToken);

    /// <summary>
    /// Returns the live <see cref="EmailCodeRowPurpose.SignIn"/> row whose <see cref="EmailCodeEntry.LinkTokenHash"/>
    /// is <paramref name="linkTokenHash"/>, or <see langword="null"/>.
    /// </summary>
    Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(
        string linkTokenHash,
        EmailCodeLiveness liveness,
        CancellationToken cancellationToken);

    /// <summary>
    /// Adds one to <see cref="EmailCodeEntry.Attempts"/> if the row is live, and returns whether it did.
    /// AuthEndpoints compares a submitted code only after this returns <see langword="true"/>, so a row is compared
    /// at most <see cref="EmailCodeLiveness.MaxAttempts"/> times.
    /// </summary>
    Task<bool> TryReserveAttemptAsync(string id, EmailCodeLiveness liveness, CancellationToken cancellationToken);

    /// <summary>
    /// Subtracts one from <see cref="EmailCodeEntry.Attempts"/> if the row is not consumed and has at least one attempt,
    /// and returns whether it did. Used when a reserved attempt ends without a wrong code, such as a missing second factor.
    /// </summary>
    Task<bool> TryReleaseAttemptAsync(string id, CancellationToken cancellationToken);

    /// <summary>
    /// Sets <see cref="EmailCodeEntry.ConsumedAt"/> to <see cref="EmailCodeLiveness.Now"/> if the row is live, and
    /// returns whether it did. With <paramref name="attemptReserved"/>, the caller holds one reserved attempt, so the row
    /// also counts as live when <see cref="EmailCodeEntry.Attempts"/> equals <see cref="EmailCodeLiveness.MaxAttempts"/>.
    /// </summary>
    Task<bool> TryConsumeAsync(
        string id,
        EmailCodeLiveness liveness,
        bool attemptReserved,
        CancellationToken cancellationToken);

    /// <summary>
    /// Clears <see cref="EmailCodeEntry.ConsumedAt"/> if it is set, and returns whether it did. Used when sign-in fails
    /// after the code was consumed, such as a recovery code that could not be redeemed.
    /// </summary>
    Task<bool> TryUnconsumeAsync(string id, CancellationToken cancellationToken);

    /// <summary>
    /// Counts the rows for the address and purpose created at or after <paramref name="since"/>, live or not.
    /// </summary>
    Task<int> CountIssuedSinceAsync(
        string emailHash,
        EmailCodeRowPurpose purpose,
        DateTime since,
        CancellationToken cancellationToken);
}

/// <summary>
/// When a row is live: <see cref="EmailCodeEntry.ConsumedAt"/> and <see cref="EmailCodeEntry.SupersededAt"/> are
/// <see langword="null"/>, <see cref="EmailCodeEntry.Attempts"/> is below <paramref name="MaxAttempts"/>, and
/// <see cref="EmailCodeEntry.ExpiresAt"/> is after <paramref name="Now"/>.
/// </summary>
/// <param name="Now">The current UTC time.</param>
/// <param name="MaxAttempts"><see cref="EmailCodeOptions.MaxAttempts"/>.</param>
public readonly record struct EmailCodeLiveness(DateTime Now, int MaxAttempts);

/// <summary>The rules <see cref="IEmailCodeStore.IssueAsync"/> applies before it inserts a row.</summary>
public sealed class EmailCodeIssueRules
{
    /// <summary>The current time and attempt limit. Rows live by this rule are superseded.</summary>
    public required EmailCodeLiveness Liveness { get; init; }

    /// <summary>
    /// When set, the row is not issued if a row for the same address and purpose was created after this time.
    /// <see langword="null"/> when <see cref="EmailCodeOptions.ResendCooldown"/> is zero.
    /// </summary>
    public DateTime? CooldownSince { get; init; }

    /// <summary>Rows for the same address and purpose that expired before this time are deleted.</summary>
    public required DateTime DeleteExpiredBefore { get; init; }
}

/// <summary>The outcome of <see cref="IEmailCodeStore.IssueAsync"/>.</summary>
public enum EmailCodeIssueStatus
{
    /// <summary>The row was inserted.</summary>
    Issued = 0,

    /// <summary>A row was created within the resend cooldown. Nothing was stored.</summary>
    Cooldown = 1,

    /// <summary>The store could not issue atomically, for example a persistent serialization failure. Nothing was stored.</summary>
    Conflict = 2,
}
