using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Services;

/// <summary>
/// Use <see cref="DefaultJwtFactory"/> to create a jwt.
/// </summary>
public class DefaultJwtFactory : IJwtFactory
{
    private readonly JwtSecurityTokenHandler tokenHandler;

    public DefaultJwtFactory(JwtSecurityTokenHandler tokenHandler)
    {
        this.tokenHandler = tokenHandler;
    }

    /// <summary>
    /// Use this method to create a jwt
    /// </summary>
    /// <param name="key"></param>
    /// <param name="algorithm"></param>
    /// <param name="payload"></param>
    /// <returns>a jwt in string</returns>
    public string Create(SecurityKey key, string algorithm, JwtPayload payload)
    {
        var credentials = new SigningCredentials(key, algorithm);
        var header = new JwtHeader(credentials);
        return tokenHandler.WriteToken(new JwtSecurityToken(header, payload));
    }
}
