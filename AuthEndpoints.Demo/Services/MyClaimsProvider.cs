using AuthEndpoints.Demo.Models;
using AuthEndpoints.Services.Claims;
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
}
