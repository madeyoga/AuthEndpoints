namespace AuthEndpoints.Services.TokenGenerators;

using AuthEndpoints.Models.Configurations;
using AuthEndpoints.Services.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class AccessJwtGenerator<TUser> : IAccessTokenGenerator<TUser>
    where TUser : class
{
    private readonly AuthenticationConfiguration configuration;
    private readonly IClaimsProvider<TUser> claimsProvider;

    public AccessJwtGenerator(IClaimsProvider<TUser> claimsProvider, AuthenticationConfiguration configuration)
    {
        this.claimsProvider = claimsProvider;
        this.configuration = configuration;
    }

    public string GenerateToken(TUser user)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.AccessTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        List<Claim> claims = claimsProvider.provideAccessTokenClaims(user);

        JwtSecurityToken token = new JwtSecurityToken(
            configuration.Issuer,
            configuration.Audience,
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(configuration.AccessTokenExpirationMinutes),
            credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

