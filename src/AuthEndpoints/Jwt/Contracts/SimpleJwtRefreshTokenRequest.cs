namespace AuthEndpoints.Jwt;

/// <summary>
/// the dto used for refresh request
/// </summary>
public class SimpleJwtRefreshTokenRequest
{
    public required string RefreshToken { get; set; }
}
