using System.Security.Claims;

namespace AuthEndpoints.Services.Providers;

public interface IClaimsProvider<TUser>
{
    List<Claim> provideClaims(TUser user);
}
