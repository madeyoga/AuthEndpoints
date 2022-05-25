using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthEndpoints.Services;

/// <summary>
/// Use <see cref="DefaultJwtFactory"/> to create a jwt with HS256 based signature
/// </summary>
public class DefaultJwtFactory : IJwtFactory
{
    private readonly JwtSecurityTokenHandler tokenHandler;

    public DefaultJwtFactory(JwtSecurityTokenHandler tokenHandler)
    {
        this.tokenHandler = tokenHandler;
    }

    /// <summary>
    /// Use this method to create a HS256-based jwt
    /// </summary>
    /// <param name="secret"></param>
    /// <param name="issuer"></param>
    /// <param name="audience"></param>
    /// <param name="claims"></param>
    /// <param name="expirationMinutes"></param>
    /// <returns>a jwt in string</returns>
    public string Create(string secret, string issuer, string audience, IList<Claim> claims, int expirationMinutes)
    {
        return Create(secret, new JwtPayload(
            issuer,
            audience,
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(expirationMinutes))
        );
    }

    /// <summary>
    /// Use this method to create a HS256-based jwt
    /// </summary>
    /// <param name="secret"></param>
    /// <param name="payload"></param>
    /// <returns>a jwt in string</returns>
    public string Create(string secret, JwtPayload payload)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var header = new JwtHeader(credentials);

        return tokenHandler.WriteToken(new JwtSecurityToken(header, payload));
    }
}
