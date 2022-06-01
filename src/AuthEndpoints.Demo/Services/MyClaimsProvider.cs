using AuthEndpoints.Demo.Models;
using AuthEndpoints.Services;
using System.Security.Claims;

namespace AuthEndpoints.Demo.Services;

public class MyClaimsProvider : IClaimsProvider<MyCustomIdentityUser>
{
    public IList<Claim> provideAccessClaims(MyCustomIdentityUser user)
    {
        throw new NotImplementedException();
    }

    public IList<Claim> provideRefreshClaims(MyCustomIdentityUser user)
    {
        throw new NotImplementedException();
    }
}
