namespace AuthEndpoints.Services.TokenGenerators;

using AuthEndpoints.Options;
using AuthEndpoints.Services.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class AccessTokenGenerator<TUser> : IAccessTokenGenerator<TUser>
    where TUser : class
{
    private readonly AuthEndpointsOptions options;
    private readonly IClaimsProvider<TUser> claimsProvider;

    public AccessTokenGenerator(IClaimsProvider<TUser> claimsProvider, AuthEndpointsOptions options)
    {
        this.claimsProvider = claimsProvider;
        this.options = options;
    }

    public string GenerateToken(TUser user)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.AccessTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        List<Claim> claims = claimsProvider.provideAccessTokenClaims(user);

        JwtSecurityToken token = new JwtSecurityToken(
            options.Issuer,
            options.Audience,
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(options.AccessTokenExpirationMinutes),
            credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

