using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IJwtFactory"/> to define your jwt generator
/// </summary>
public interface IJwtFactory
{
    /// <summary>
    /// Method for creating a jwt
    /// </summary>
    /// <param name="key"></param>
    /// <param name="algorithm"></param>
    /// <param name="payload"></param>
    /// <returns></returns>
    public string Create(SecurityKey key, string algorithm, JwtPayload payload);
}
