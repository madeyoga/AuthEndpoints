using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Services;

/// <summary>
/// Use <see cref="DefaultClaimsProvider{TUserKey, TUser}"/> to get access token claims and refresh token claims
/// </summary>
/// <typeparam name="TUserKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
public class DefaultClaimsProvider<TUserKey, TUser> : IClaimsProvider<TUser>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    /// <summary>
    /// Provide claims for access token
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    public IList<Claim> provideAccessClaims(TUser user)
    {
        return new List<Claim>()
        {
            new Claim("id", user.Id.ToString()!),
            new Claim(ClaimTypes.Name, user.UserName),
        };
    }

    /// <summary>
    /// Provide claims for refresh token
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    public IList<Claim> provideRefreshClaims(TUser user)
    {
        return new List<Claim>()
        {
            new Claim("id", user.Id.ToString()!),
        };
    }
}
