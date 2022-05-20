using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace AuthEndpoints.Services;

internal class AsymAccessTokenGenerator<TUser> : IAccessTokenGenerator<TUser>
    where TUser : class
{
    private readonly IOptions<AuthEndpointsOptions> options;
    private readonly IAccessTokenClaimsProvider<TUser> claimsProvider;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public AsymAccessTokenGenerator(IAccessTokenClaimsProvider<TUser> claimsProvider, IOptions<AuthEndpointsOptions> options, JwtSecurityTokenHandler tokenHandler)
    {
        this.claimsProvider = claimsProvider;
        this.options = options;
        this.tokenHandler = tokenHandler;
    }

    public string Generate(TUser user)
    {
        var rsa = RSA.Create();
        string key = options.Value.AccessTokenSecret!;
        rsa.FromXmlString(key);
        var credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var header = new JwtHeader(credentials);
        var payload = new JwtPayload(
            options.Value.Issuer,
            options.Value.Audience,
            claimsProvider.provideClaims(user),
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(options.Value.AccessTokenExpirationMinutes)
        );

        return tokenHandler.WriteToken(new JwtSecurityToken(header, payload));
    }
}
