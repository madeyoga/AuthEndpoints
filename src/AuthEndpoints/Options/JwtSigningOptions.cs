using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

public class JwtSigningOptions
{
    public SecurityKey? SigningKey { get; set; }
    public string Algorithm { get; set; } = SecurityAlgorithms.HmacSha256;
    public int ExpirationMinutes { get; set; } = 120;
}
