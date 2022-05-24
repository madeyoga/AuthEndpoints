namespace AuthEndpoints.Models;

/// <summary>
/// the dto used to send an authenticated user response containing access token and refresh token
/// </summary>
public class AuthenticatedUserResponse
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
}