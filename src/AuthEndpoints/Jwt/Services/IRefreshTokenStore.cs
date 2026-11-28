namespace AuthEndpoints.Jwt;

/// <summary>
/// Reads and writes JWT refresh-token rows (<see cref="RefreshToken"/>). <see cref="RefreshTokenService"/> generates and
/// hashes tokens and decides lifetimes and reuse detection; a store only stores rows. A store never sees a raw token.
/// </summary>
/// <remarks>
/// Each method is one atomic operation. <see cref="TryRotateAsync"/> is the one that matters most: of two concurrent
/// rotations of one token, exactly one may succeed. Times are UTC.
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>Returns the token whose <see cref="RefreshToken.TokenHash"/> is <paramref name="tokenHash"/>, revoked or not.</summary>
    Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken);

    /// <summary>Inserts <paramref name="token"/>.</summary>
    Task CreateAsync(RefreshToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically: if the token with id <paramref name="presentedId"/> is not revoked, sets its
    /// <see cref="RefreshToken.RevokedAt"/> to <paramref name="revokedAt"/> and its
    /// <see cref="RefreshToken.ReplacedByTokenId"/> to <paramref name="successor"/>'s id, inserts
    /// <paramref name="successor"/>, and returns <see langword="true"/>. Otherwise changes nothing and returns
    /// <see langword="false"/>. The update and the insert succeed or fail together.
    /// </summary>
    Task<bool> TryRotateAsync(
        string presentedId,
        RefreshToken successor,
        DateTime revokedAt,
        CancellationToken cancellationToken);

    /// <summary>Sets <see cref="RefreshToken.RevokedAt"/> on the token if it is not revoked.</summary>
    Task RevokeAsync(string id, DateTime revokedAt, CancellationToken cancellationToken);

    /// <summary>Sets <see cref="RefreshToken.RevokedAt"/> on every token of the family that is not revoked.</summary>
    Task RevokeFamilyAsync(string familyId, DateTime revokedAt, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the <see cref="RefreshToken.AbsoluteExpiresAt"/> of any token in the family, or <see langword="null"/>
    /// when the family has no tokens. Every token of a family has the same value.
    /// </summary>
    Task<DateTime?> FindFamilyAbsoluteExpiresAtAsync(string familyId, CancellationToken cancellationToken);

    /// <summary>
    /// Sets <see cref="RefreshToken.SessionId"/> on the token. Called only when active sessions are on
    /// (<c>AddActiveSessions</c>). A store that does not keep session ids may do nothing.
    /// </summary>
    Task SetSessionAsync(string tokenId, string sessionId, CancellationToken cancellationToken);

    /// <summary>Returns the distinct non-null <see cref="RefreshToken.SessionId"/> values of the family's tokens.</summary>
    Task<IReadOnlyList<string>> FindFamilySessionIdsAsync(string familyId, CancellationToken cancellationToken);

    /// <summary>Sets <see cref="RefreshToken.RevokedAt"/> on every token of those sessions that is not revoked.</summary>
    Task RevokeSessionsAsync(IReadOnlyCollection<string> sessionIds, DateTime revokedAt, CancellationToken cancellationToken);
}
