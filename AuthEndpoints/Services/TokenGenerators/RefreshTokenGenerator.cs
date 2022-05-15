using AuthEndpoints.Options;
using AuthEndpoints.Services.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthEndpoints.Services.TokenGenerators;

public class RefreshTokenGenerator<TUser> : IRefreshTokenGenerator<TUser>
    where TUser : class
{
    private readonly IClaimsProvider<TUser> claimsProvider;
    private readonly IOptions<AuthEndpointsOptions> options;

    public RefreshTokenGenerator(IClaimsProvider<TUser> claimsProvider, IOptions<AuthEndpointsOptions> options)
    {
        this.claimsProvider = claimsProvider;
        this.options = options;
    }

    public string GenerateToken(TUser user)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.RefreshTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken token = new JwtSecurityToken(
            options.Value.RefreshTokenValidationParameters!.ValidIssuer,
            options.Value.RefreshTokenValidationParameters!.ValidAudience,
            claimsProvider.provideRefreshTokenClaims(user),
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(options.Value.RefreshTokenExpirationMinutes),
            credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
