using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Manages hashed refresh tokens with family-based reuse detection and an absolute family lifetime,
/// over an <see cref="IRefreshTokenStore"/>.
/// </summary>
public class RefreshTokenService : IRefreshTokenService
{
    private readonly IRefreshTokenStore _store;
    private readonly TimeProvider _time;
    private readonly SimpleJwtOptions _session;

    public RefreshTokenService(IRefreshTokenStore store, TimeProvider time, IOptions<SimpleJwtOptions> sessionOptions)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(sessionOptions);
        _store = store;
        _time = time;
        _session = sessionOptions.Value;
    }

    public Task<RefreshToken?> GetRefreshTokenAsync(string rawToken, CancellationToken cancellationToken = default)
    {
        return _store.FindByHashAsync(HashToken(rawToken), cancellationToken);
    }

    public async Task<RefreshToken?> RotateAsync(
        RefreshToken refreshToken,
        string securityStamp,
        CancellationToken cancellationToken = default)
    {
        var now = UtcNow;
        var absoluteExpiresAt = AsUtc(refreshToken.AbsoluteExpiresAt);
        if (refreshToken.RevokedAt != null
            || AsUtc(refreshToken.ExpiresAt) <= now
            || absoluteExpiresAt <= now)
        {
            return null;
        }

        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var expiresAt = now.Add(_session.RefreshTokenLifetime);
        if (expiresAt > absoluteExpiresAt)
        {
            expiresAt = absoluteExpiresAt;
        }

        var successor = new RefreshToken
        {
            TokenHash = HashToken(rawToken),
            FamilyId = refreshToken.FamilyId,
            SecurityStamp = securityStamp,
            UserId = refreshToken.UserId,
            ExpiresAt = expiresAt,
            AbsoluteExpiresAt = absoluteExpiresAt,
            SessionId = refreshToken.SessionId,
        };

        // Compare-and-swap: only one concurrent rotator can revoke a still-live token.
        // The raw token is attached only after the store call, so a store never sees it.
        if (!await _store.TryRotateAsync(refreshToken.Id, successor, now, cancellationToken))
        {
            // The winner has stored its successor. Reuse of this token revokes the family,
            // including that successor, so parallel refreshes sign every client out.
            // Not cancellable: an aborted request must not skip reuse detection.
            await RevokeFamilyAsync(refreshToken.FamilyId, CancellationToken.None);
            return null;
        }

        successor.Token = rawToken;
        refreshToken.RevokedAt = now;
        refreshToken.ReplacedByTokenId = successor.Id;
        return successor;
    }

    public async Task RevokeAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default)
    {
        var now = UtcNow;
        await _store.RevokeAsync(refreshToken.Id, now, cancellationToken);
        refreshToken.RevokedAt ??= now;
    }

    public Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default)
    {
        return _store.RevokeFamilyAsync(familyId, UtcNow, cancellationToken);
    }

    public async Task<RefreshToken> CreateAsync(
        string userId,
        string securityStamp,
        string? familyId = null,
        CancellationToken cancellationToken = default)
    {
        var now = UtcNow;
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var absoluteExpiresAt = await ResolveAbsoluteExpiresAtAsync(familyId, now, cancellationToken);
        var expiresAt = now.Add(_session.RefreshTokenLifetime);
        if (expiresAt > absoluteExpiresAt)
        {
            expiresAt = absoluteExpiresAt;
        }

        var newRefreshToken = new RefreshToken
        {
            TokenHash = HashToken(rawToken),
            FamilyId = familyId ?? Guid.NewGuid().ToString(),
            SecurityStamp = securityStamp,
            UserId = userId,
            ExpiresAt = expiresAt,
            AbsoluteExpiresAt = absoluteExpiresAt,
        };

        await _store.CreateAsync(newRefreshToken, cancellationToken);
        newRefreshToken.Token = rawToken;
        return newRefreshToken;
    }

    public bool IsValid(RefreshToken refreshToken)
    {
        var now = UtcNow;
        return AsUtc(refreshToken.ExpiresAt) > now
            && AsUtc(refreshToken.AbsoluteExpiresAt) > now
            && refreshToken.RevokedAt == null;
    }

    internal static string HashToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes);
    }

    private async Task<DateTime> ResolveAbsoluteExpiresAtAsync(string? familyId, DateTime now, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(familyId))
        {
            return now.Add(_session.AbsoluteLifetime);
        }

        // Joining a family must not start a new absolute window.
        var existing = await _store.FindFamilyAbsoluteExpiresAtAsync(familyId, cancellationToken);
        return existing is { } found ? AsUtc(found) : now.Add(_session.AbsoluteLifetime);
    }

    private DateTime UtcNow => AsUtc(_time.GetUtcNow().UtcDateTime);

    private static DateTime AsUtc(DateTime value) =>
        value.Kind == DateTimeKind.Utc ? value : DateTime.SpecifyKind(value, DateTimeKind.Utc);
}
