using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthEndpoints.Services;

/// <summary>
/// Use this class to generate refresh jwt for the given user
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class RefreshTokenGenerator<TUser> : IRefreshTokenGenerator<TUser>
    where TUser : class
{
    private readonly IRefreshTokenClaimsProvider<TUser> claimsProvider;
    private readonly IOptions<AuthEndpointsOptions> options;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public RefreshTokenGenerator(IRefreshTokenClaimsProvider<TUser> claimsProvider, IOptions<AuthEndpointsOptions> options, JwtSecurityTokenHandler tokenHandler)
    {
        this.claimsProvider = claimsProvider;
        this.options = options;
        this.tokenHandler = tokenHandler;
    }

    /// <summary>
    /// Use this method to generate a refresh jwt for the given user
    /// </summary>
    /// <param name="user"></param>
    /// <returns>A jwt string</returns>
    public string Generate(TUser user)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.RefreshTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken token = new JwtSecurityToken(
            options.Value.RefreshTokenValidationParameters!.ValidIssuer,
            options.Value.RefreshTokenValidationParameters!.ValidAudience,
            claimsProvider.provideClaims(user),
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(options.Value.RefreshTokenExpirationMinutes),
            credentials);

        return tokenHandler.WriteToken(token);
    }
}
