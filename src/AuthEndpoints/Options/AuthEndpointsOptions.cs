using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints;

/// <summary>
/// Represents all the options you can use to configure the AuthEndpoints system.
/// </summary>
public class AuthEndpointsOptions
{
    public const string Key = "AuthEndpoints";
    [Required]
    public string? AccessTokenSecret { get; set; }
    [Required]
    public string? RefreshTokenSecret { get; set; }
    [Required]
    public string? Issuer { get; set; }
    [Required]
    public string? Audience { get; set; }
    public int AccessTokenExpirationMinutes { get; set; } = 120;
    public int RefreshTokenExpirationMinutes { get; set; } = 2880;

    public TokenValidationParameters? AccessTokenValidationParameters { get; set; }
    public TokenValidationParameters? RefreshTokenValidationParameters { get; set; }
}
