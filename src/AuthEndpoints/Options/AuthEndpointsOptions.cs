using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

/// <summary>
/// Represents all the options you can use to configure the AuthEndpoints system.
/// </summary>
public class AuthEndpointsOptions
{
    public const string Key = "AuthEndpoints";
    public string? AccessTokenSecret { get; set; }
    public string? RefreshTokenSecret { get; set; }
    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    public int AccessTokenExpirationMinutes { get; set; }
    public int RefreshTokenExpirationMinutes { get; set; }

    public TokenValidationParameters? AccessTokenValidationParameters { get; set; }
    public TokenValidationParameters? RefreshTokenValidationParameters { get; set; }
}
