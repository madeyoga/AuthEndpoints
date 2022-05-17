using AuthEndpoints.Demo.Models;
using AuthEndpoints.Services;
using System.Security.Claims;

namespace AuthEndpoints.Demo.Services;

public class MyClaimsProvider : IClaimsProvider<MyCustomIdentityUser>
{
    public IList<Claim> provideClaims(MyCustomIdentityUser user)
    {
        throw new NotImplementedException();
    }
}
