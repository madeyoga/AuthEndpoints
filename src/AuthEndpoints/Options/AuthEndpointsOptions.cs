using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

/// <summary>
/// Represents all the options you can use to configure the AuthEndpoints system.
/// </summary>
public class AuthEndpointsOptions
{
    public const string Key = "AuthEndpoints";
    public string? Issuer { get; set; }
    public string? Audience { get; set; }

    public JwtSigningOptions AccessSigningOptions { get; set; } = new JwtSigningOptions()
    {
        Algorithm = SecurityAlgorithms.HmacSha256,
        ExpirationMinutes = 120
    };
    public JwtSigningOptions RefreshSigningOptions { get; set; } = new JwtSigningOptions()
    {
        Algorithm = SecurityAlgorithms.HmacSha256,
        ExpirationMinutes = 2880
    };
    public TokenValidationParameters? AccessValidationParameters { get; set; }
    public TokenValidationParameters? RefreshValidationParameters { get; set; }
}
