namespace AuthEndpoints.Services;

using AuthEndpoints;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

/// <summary>
/// Use this class to generate an access jwt for the given user
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class AccessTokenGenerator<TUser> : IAccessTokenGenerator<TUser>
    where TUser : class
{
    private readonly IOptions<AuthEndpointsOptions> options;
    private readonly IAccessTokenClaimsProvider<TUser> claimsProvider;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public AccessTokenGenerator(IAccessTokenClaimsProvider<TUser> claimsProvider, IOptions<AuthEndpointsOptions> options, JwtSecurityTokenHandler tokenHandler)
    {
        this.claimsProvider = claimsProvider;
        this.options = options;
        this.tokenHandler = tokenHandler;
    }

    /// <summary>
    /// Use this method to generate an access jwt for the given user
    /// </summary>
    /// <param name="user"></param>
    /// <returns>JSON Web Token in <see cref="string"/></returns>
    public string Generate(TUser user)
    {
        SecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.AccessTokenSecret!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        IList<Claim> claims = claimsProvider.provideClaims(user);

        var header = new JwtHeader(credentials);
        var payload = new JwtPayload(
            options.Value.Issuer, 
            options.Value.Audience, 
            claims, 
            DateTime.UtcNow, 
            DateTime.UtcNow.AddMinutes(options.Value.AccessTokenExpirationMinutes)
        );

        JwtSecurityToken token = new JwtSecurityToken(header, payload);

        return tokenHandler.WriteToken(token);
    }
}

