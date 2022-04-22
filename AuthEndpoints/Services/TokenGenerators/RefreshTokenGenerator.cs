namespace AuthEndpoints.Services.TokenGenerators;

using AuthEndpoints.Models.Configurations;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

public class RefreshTokenGenerator<TUserKey, TUser> : ITokenGenerator<TUser>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    private readonly AuthenticationConfiguration configuration;

    public RefreshTokenGenerator(AuthenticationConfiguration configuration)
    {
        this.configuration = configuration;
    }

    public string GenerateToken(TUser user)
    {
        // key used to sign jwt is gonna be the same as the key used for verify jwt
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.RefreshTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken token = new JwtSecurityToken(
            configuration.Issuer, // issuer domain
            configuration.Audience, // audience
            null, // claims
            DateTime.UtcNow, // token valid datetime
            DateTime.UtcNow.AddMinutes(configuration.RefreshTokenExpirationMinutes), // token expired datetime
            credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
