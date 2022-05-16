namespace AuthEndpoints.Models.Responses;

public class AuthenticatedJwtResponse
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
}
