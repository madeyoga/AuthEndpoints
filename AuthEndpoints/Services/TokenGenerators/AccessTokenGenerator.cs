namespace AuthEndpoints.Services.TokenGenerators;

using AuthEndpoints.Models.Configurations;
using AuthEndpoints.Services.Providers;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class AccessTokenGenerator<TUserKey, TUser> : ITokenGenerator<TUser>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    private readonly AuthenticationConfiguration configuration;
    private readonly IClaimsProvider<TUser> claimsProvider;

    public AccessTokenGenerator(IClaimsProvider<TUser> claimsProvider, AuthenticationConfiguration configuration)
    {
        this.claimsProvider = claimsProvider;
        this.configuration = configuration;
    }

    public string GenerateToken(TUser user)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.AccessTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        List<Claim> claims = claimsProvider.provideClaims(user);

        JwtSecurityToken token = new JwtSecurityToken(
            configuration.Issuer,
            configuration.Audience,
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(configuration.AccessTokenExpirationMinutes),
            credentials
        );

        // get the string of jwt token
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

