using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthEndpoints.Services;

/// <summary>
/// Use <see cref="RsaSignedJwtFactory"/> to create a jwt with RS256 signature.
/// </summary>
public class RsaSignedJwtFactory : IJwtFactory
{
    private readonly JwtSecurityTokenHandler tokenHandler;

    public RsaSignedJwtFactory(JwtSecurityTokenHandler tokenHandler)
    {
        this.tokenHandler = tokenHandler;
    }

    /// <summary>
    /// Use this method to create a jwt
    /// </summary>
    /// <param name="secret"></param>
    /// <param name="issuer"></param>
    /// <param name="audience"></param>
    /// <param name="claims"></param>
    /// <param name="expirationMinutes"></param>
    /// <returns>a jwt in string</returns>
    public string Create(string secret, string issuer, string audience, IList<Claim> claims, int expirationMinutes)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(secret);

        var credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var header = new JwtHeader(credentials);
        var payload = new JwtPayload(
            issuer,
            audience,
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(expirationMinutes)
        );

        return tokenHandler.WriteToken(new JwtSecurityToken(header, payload));
    }
}
