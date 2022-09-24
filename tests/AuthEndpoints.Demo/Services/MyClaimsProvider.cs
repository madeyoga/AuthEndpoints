using System.Security.Claims;
using AuthEndpoints.SimpleJwt.Core.Services;

namespace AuthEndpoints.Demo.Services;

public class MyClaimsProvider : IClaimsProvider
{

    public IEnumerable<Claim> ProvideAccessClaims(ClaimsPrincipal user)
    {
        throw new NotImplementedException();
    }

    public IEnumerable<Claim> ProvideRefreshClaims(ClaimsPrincipal user)
    {
        throw new NotImplementedException();
    }
}
