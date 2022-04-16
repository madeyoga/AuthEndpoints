namespace AuthEndpoints.Jwt.Models.Responses;

public class AuthenticatedUserResponse
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
}
