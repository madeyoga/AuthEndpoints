using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Options;

public class AuthEndpointsOptions 
{
    public const string Key = "AuthEndpointsOptions";
    public string? AccessTokenSecret { get; set; }
    public string? RefreshTokenSecret { get; set; }
    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    public int AccessTokenExpirationMinutes { get; set; }
    public int RefreshTokenExpirationMinutes { get; set; }

    public TokenValidationParameters? AccessTokenValidationParameters { get; set; }
    public TokenValidationParameters? RefreshTokenValidationParameters { get; set; }
}
