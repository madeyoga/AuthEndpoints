namespace AuthEndpoints.Jwt;

/// <summary>
/// Refresh token model
/// </summary>
public class RefreshToken
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public required string Token { get; init; }
    public required string UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
}
