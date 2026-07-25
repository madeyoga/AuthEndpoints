using System.ComponentModel.DataAnnotations.Schema;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Refresh token model. The database stores only <see cref="TokenHash"/>;
/// <see cref="Token"/> is populated when a new token is issued for the cookie.
/// </summary>
public class RefreshToken
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>SHA-256 hash of the raw cookie value (unique).</summary>
    public required string TokenHash { get; set; }

    /// <summary>Groups rotations for a single login session (reuse detection).</summary>
    public required string FamilyId { get; set; }

    /// <summary>Successor token id after rotation; used for reuse detection.</summary>
    public string? ReplacedByTokenId { get; set; }

    /// <summary>Security stamp captured at issue time; refresh fails if it no longer matches.</summary>
    public required string SecurityStamp { get; set; }

    public required string UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }

    /// <summary>Raw token for the cookie. Not persisted.</summary>
    [NotMapped]
    public string? Token { get; set; }
}
