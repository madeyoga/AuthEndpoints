using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

/// <summary>
/// Represents all the options you can use to configure the AuthEndpoints system.
/// </summary>
public class AuthEndpointsOptions
{
    public const string Key = "AuthEndpoints";
    public string? AccessSecret { get; set; }
    public string? RefreshSecret { get; set; }
    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    public int AccessExpirationMinutes { get; set; } = 120;
    public int RefreshExpirationMinutes { get; set; } = 2880;

    public TokenValidationParameters? AccessValidationParameters { get; set; }
    public TokenValidationParameters? RefreshValidationParameters { get; set; }
}
