using AuthEndpoints.Demo.Models;
using AuthEndpoints.Services.Providers;
using System.Security.Claims;

namespace AuthEndpoints.Demo.Services;

public class MyClaimsProvider : IClaimsProvider<MyCustomIdentityUser>
{
    public List<Claim> provideClaims(MyCustomIdentityUser user)
    {
        return new List<Claim>()
        {
        };
    }
}
