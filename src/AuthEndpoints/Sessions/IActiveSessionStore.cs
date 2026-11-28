namespace AuthEndpoints.Sessions;

/// <summary>
/// Reads and writes active-session rows (<see cref="ActiveSession"/>) for <c>AddActiveSessions</c>. AuthEndpoints decides
/// when a session starts, is touched, and ends; a store only stores rows. With JWT, the link from refresh tokens to
/// sessions is kept by <see cref="Jwt.IRefreshTokenStore"/>, so this store touches only its own rows.
/// </summary>
/// <remarks>Each method is one atomic operation. Times are UTC.</remarks>
public interface IActiveSessionStore
{
    /// <summary>
    /// Inserts <paramref name="session"/> unless a session with its <see cref="ActiveSession.Id"/> exists, and returns
    /// whether it inserted. Of two concurrent creates of one id, the first is kept and the second returns
    /// <see langword="false"/> without throwing.
    /// </summary>
    Task<bool> TryCreateAsync(ActiveSession session, CancellationToken cancellationToken);

    /// <summary>Returns the session, revoked or expired or not, or <see langword="null"/>.</summary>
    Task<ActiveSession?> FindAsync(string id, CancellationToken cancellationToken);

    /// <summary>
    /// If the session is not revoked, sets <see cref="ActiveSession.LastSeenAt"/>, and <see cref="ActiveSession.ExpiresAt"/>
    /// when <paramref name="expiresAt"/> is set.
    /// </summary>
    Task TouchAsync(string id, DateTime lastSeenAt, DateTime? expiresAt, CancellationToken cancellationToken);

    /// <summary>
    /// If the session is not revoked, sets <see cref="ActiveSession.SecurityStamp"/> and
    /// <see cref="ActiveSession.LastSeenAt"/>, and <see cref="ActiveSession.ExpiresAt"/> when <paramref name="expiresAt"/> is set.
    /// </summary>
    Task UpdateStampAsync(
        string id,
        string securityStamp,
        DateTime lastSeenAt,
        DateTime? expiresAt,
        CancellationToken cancellationToken);

    /// <summary>Sets <see cref="ActiveSession.RevokedAt"/> on each of the sessions that is not revoked.</summary>
    Task RevokeAsync(IReadOnlyCollection<string> ids, DateTime revokedAt, CancellationToken cancellationToken);

    /// <summary>Returns the user's sessions that are not revoked and expire after <paramref name="now"/>.</summary>
    Task<IReadOnlyList<ActiveSession>> ListActiveAsync(string userId, DateTime now, CancellationToken cancellationToken);

    /// <summary>Returns the ids of the user's sessions that are not revoked, expired or not.</summary>
    Task<IReadOnlyList<string>> ListUnrevokedIdsAsync(string userId, CancellationToken cancellationToken);

    /// <summary>Deletes the sessions that are revoked, or expire at or before <paramref name="now"/>, and returns how many.</summary>
    Task<int> DeleteEndedAsync(DateTime now, CancellationToken cancellationToken);
}
