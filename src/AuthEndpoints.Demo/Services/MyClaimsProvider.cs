using AuthEndpoints.Demo.Models;
using AuthEndpoints.Services;
using System.Security.Claims;

namespace AuthEndpoints.Demo.Services;

public class MyClaimsProvider : IClaimsProvider<MyCustomIdentityUser>
{
    public List<Claim> provideAccessTokenClaims(MyCustomIdentityUser user)
    {
        return new List<Claim>()
        {
        };
    }

    public List<Claim> provideRefreshTokenClaims(MyCustomIdentityUser user)
    {
        return new List<Claim>()
        {
        };
    }
}
