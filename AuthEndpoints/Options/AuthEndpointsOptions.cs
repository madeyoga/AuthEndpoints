namespace AuthEndpoints.Options;

public class AuthEndpointsOptions
{
    public string? AccessTokenSecret { get; set; }
    public int AccessTokenExpirationMinutes { get; set; }
    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    public string? RefreshTokenSecret { get; set; }
    public int RefreshTokenExpirationMinutes { get; set; }
}
