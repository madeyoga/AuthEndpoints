namespace AuthEndpoints.Jwt;
public class AuthenticationError
{
    public required string Code { get; set; }
    public required string Description { get; set; }
}
