using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IJwtFactory"/> to define your jwt generator
/// </summary>
public interface IJwtFactory
{
    /// <summary>
    /// Create a jwt
    /// </summary>
    /// <param name="secret"></param>
    /// <param name="issuer"></param>
    /// <param name="audience"></param>
    /// <param name="claims"></param>
    /// <param name="expirationMinutes"></param>
    /// <returns>a jwt in string</returns>
    string Create(string secret, string issuer, string audience, IList<Claim> claims, int expirationMinutes);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="secret"></param>
    /// <param name="payload"></param>
    /// <returns></returns>
    string Create(string secret, JwtPayload payload);
}
