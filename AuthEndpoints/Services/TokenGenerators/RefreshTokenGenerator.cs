namespace AuthEndpoints.Services.TokenGenerators;

using AuthEndpoints.Models.Configurations;
using AuthEndpoints.Services.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

public class RefreshTokenGenerator<TUser> : IRefreshTokenGenerator<TUser>
    where TUser : class
{
    private readonly IClaimsProvider<TUser> claimsProvider;
    private readonly AuthenticationConfiguration configuration;

    public RefreshTokenGenerator(IClaimsProvider<TUser> claimsProvider, AuthenticationConfiguration configuration)
    {
        this.claimsProvider = claimsProvider;
        this.configuration = configuration;
    }

    public string GenerateToken(TUser user)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.RefreshTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken token = new JwtSecurityToken(
            configuration.Issuer,
            configuration.Audience,
            claimsProvider.provideRefreshTokenClaims(user),
            DateTime.UtcNow, // token valid datetime
            DateTime.UtcNow.AddMinutes(configuration.RefreshTokenExpirationMinutes), // token expired datetime
            credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
