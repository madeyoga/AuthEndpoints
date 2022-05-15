namespace AuthEndpoints.Services.TokenGenerators;

using AuthEndpoints.Options;
using AuthEndpoints.Services.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class AccessTokenGenerator<TUser> : IAccessTokenGenerator<TUser>
    where TUser : class
{
    private readonly IOptions<AuthEndpointsOptions> options;
    private readonly IClaimsProvider<TUser> claimsProvider;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public AccessTokenGenerator(IClaimsProvider<TUser> claimsProvider, IOptions<AuthEndpointsOptions> options, JwtSecurityTokenHandler tokenHandler)
    {
        this.claimsProvider = claimsProvider;
        this.options = options;
        this.tokenHandler = tokenHandler;
    }

    public string Generate(TUser user)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.AccessTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        List<Claim> claims = claimsProvider.provideAccessTokenClaims(user);

        JwtSecurityToken token = new JwtSecurityToken(
            options.Value.Issuer,
            options.Value.Audience,
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(options.Value.AccessTokenExpirationMinutes),
            credentials
        );

        return tokenHandler.WriteToken(token);
    }
}

