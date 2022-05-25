using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

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

    public string Create(SecurityKey key, string algorithm, JwtPayload payload)
    {
        throw new NotImplementedException();
    }
}
