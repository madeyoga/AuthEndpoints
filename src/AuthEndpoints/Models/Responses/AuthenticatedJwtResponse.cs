namespace AuthEndpoints.Models;

public class AuthenticatedJwtResponse
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
}
