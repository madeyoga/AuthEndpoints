namespace AuthEndpoints.Jwt;

/// <summary>
/// the dto used to send an authenticated user response containing access Token and refresh Token
/// </summary>
public class SimpleJwtTokenResponse
{
    public required string AccessToken { get; set; }
    public string TokenType { get; set; } = "Bearer";
}
