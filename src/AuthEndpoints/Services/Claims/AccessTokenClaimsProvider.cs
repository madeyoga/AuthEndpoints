using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AuthEndpoints.Services;

/// <summary>
/// A default service that provides claims for refresh token
/// </summary>
/// <typeparam name="TUserKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
public class AccessTokenClaimsProvider<TUserKey, TUser> : IAccessTokenClaimsProvider<TUser>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    /// <summary>
    /// Use this method to get list of claims for an access token
    /// </summary>
    /// <param name="user"></param>
    /// <returns>A list of claims</returns>
    public IList<Claim> provideClaims(TUser user)
    {
        return new List<Claim>()
        {
            new Claim("id", user.Id.ToString()!),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Name, user.UserName),
        };
    }
}
