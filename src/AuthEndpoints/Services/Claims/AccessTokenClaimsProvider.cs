using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AuthEndpoints.Services;

public class AccessTokenClaimsProvider<TUserKey, TUser> : IAccessTokenClaimsProvider<TUser>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
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
