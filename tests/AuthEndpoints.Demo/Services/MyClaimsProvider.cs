using System.Security.Claims;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.SimpleJwt.Core.Services;

namespace AuthEndpoints.Demo.Services;

public class MyClaimsProvider : IClaimsProvider<MyCustomIdentityUser>
{
    public IList<Claim> ProvideAccessClaims(MyCustomIdentityUser user)
    {
        throw new NotImplementedException();
    }

    public IList<Claim> ProvideRefreshClaims(MyCustomIdentityUser user)
    {
        throw new NotImplementedException();
    }
}
