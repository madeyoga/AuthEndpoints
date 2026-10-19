namespace AuthEndpoints.Jwt;

public class SimpleJwtRefreshTokenRequest
{
    public required string RefreshToken { get; set; }
}
