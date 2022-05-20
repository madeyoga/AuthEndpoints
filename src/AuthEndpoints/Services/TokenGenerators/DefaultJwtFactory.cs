using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthEndpoints.Services;

/// <summary>
/// Symmetric jwt factory
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class DefaultJwtFactory<TUser> : IJwtFactory<TUser>
    where TUser : class
{
    private readonly IRefreshTokenClaimsProvider<TUser> claimsProvider;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public DefaultJwtFactory(IRefreshTokenClaimsProvider<TUser> claimsProvider, JwtSecurityTokenHandler tokenHandler)
    {
        this.claimsProvider = claimsProvider;
        this.tokenHandler = tokenHandler;
    }

    /// <summary>
    /// Use this method to create a symmetric jwt
    /// </summary>
    /// <param name="user"></param>
    /// <param name="secret"></param>
    /// <param name="issuer"></param>
    /// <param name="audience"></param>
    /// <param name="expirationMinutes"></param>
    /// <returns>a jwt in string</returns>
    public string Create(TUser user, string secret, string issuer, string audience, int expirationMinutes)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var header = new JwtHeader(credentials);
        var payload = new JwtPayload(
            issuer,
            audience,
            claimsProvider.provideClaims(user),
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(expirationMinutes)
        );

        return tokenHandler.WriteToken(new JwtSecurityToken(header, payload));
    }
}
