using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AuthEndpoints.Services.Claims;

public class DefaultClaimsProvider<TUserKey, TUser> : IClaimsProvider<TUser>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
{
    public List<Claim> provideAccessTokenClaims(TUser user)
    {
        return new List<Claim>()
        {
            new Claim("id", user.Id.ToString()!),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Name, user.UserName),
        };
    }

    public List<Claim> provideRefreshTokenClaims(TUser user)
    {
        return new List<Claim>()
        {
            new Claim("id", user.Id.ToString()!),
        };
    }
}
