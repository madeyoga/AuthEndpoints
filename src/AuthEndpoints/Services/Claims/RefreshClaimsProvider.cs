using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AuthEndpoints.Services;

/// <summary>
/// A default service that provides claims for Refresh Token
/// </summary>
/// <typeparam name="TUserKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
public class RefreshClaimsProvider<TUserKey, TUser> : IRefreshClaimsProvider<TUser>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    /// <summary>
    /// Use this method to get a list of claims for a refresh token
    /// </summary>
    /// <param name="user"></param>
    /// <returns>A list of Claims</returns>
    public IList<Claim> provideClaims(TUser user)
    {
        return new List<Claim>()
        {
            new Claim("id", user.Id.ToString()!),
        };
    }
}
