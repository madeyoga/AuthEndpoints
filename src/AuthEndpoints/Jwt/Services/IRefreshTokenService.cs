namespace AuthEndpoints.Jwt;

/// <summary>
/// Issues, rotates and revokes refresh tokens. The default, <see cref="RefreshTokenService"/>, stores rows through
/// <see cref="IRefreshTokenStore"/>.
/// </summary>
/// <remarks>
/// AuthEndpoints passes the request's cancellation token to lookups, creates and rotations. It passes
/// <see cref="CancellationToken.None"/> to the revokes that reuse detection and sign-out depend on, so a client that
/// aborts its request cannot skip them.
/// </remarks>
public interface IRefreshTokenService
{
    /// <summary>Looks up a token by the raw refresh value (hashed for storage lookup).</summary>
    Task<RefreshToken?> GetRefreshTokenAsync(string rawToken, CancellationToken cancellationToken = default);

    Task RevokeAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default);

    /// <summary>Revokes every token in the family (refresh-token reuse detection).</summary>
    Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new refresh token. Returns the entity with <see cref="RefreshToken.Token"/> set to the raw value.
    /// </summary>
    Task<RefreshToken> CreateAsync(
        string userId,
        string securityStamp,
        string? familyId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically revokes <paramref name="refreshToken"/> and issues a single successor in the same family.
    /// Returns <c>null</c> when the token is already expired or revoked.
    /// Returns <c>null</c> when another request already rotated the token, and in that case revokes the family
    /// whatever <paramref name="cancellationToken"/> says.
    /// </summary>
    Task<RefreshToken?> RotateAsync(
        RefreshToken refreshToken,
        string securityStamp,
        CancellationToken cancellationToken = default);

    bool IsValid(RefreshToken refreshToken);
}
