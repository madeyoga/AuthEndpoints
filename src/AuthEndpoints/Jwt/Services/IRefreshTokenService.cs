namespace AuthEndpoints.Jwt;

public interface IRefreshTokenService
{
    /// <summary>Looks up a token by the raw cookie value (hashed for storage lookup).</summary>
    Task<RefreshToken?> GetRefreshTokenAsync(string rawToken);

    Task RevokeAsync(RefreshToken refreshToken);

    /// <summary>Revokes every token in the family (refresh-token reuse detection).</summary>
    Task RevokeFamilyAsync(string familyId);

    /// <summary>
    /// Creates a new refresh token. Returns the entity with <see cref="RefreshToken.Token"/> set to the raw value.
    /// </summary>
    Task<RefreshToken> CreateAsync(string userId, string securityStamp, string? familyId = null);

    /// <summary>
    /// Atomically revokes <paramref name="refreshToken"/> and issues a single successor in the same family.
    /// Returns <c>null</c> when another request already rotated the token (compare-and-swap lost).
    /// </summary>
    Task<RefreshToken?> RotateAsync(RefreshToken refreshToken, string securityStamp);

    bool IsValid(RefreshToken refreshToken);
}
