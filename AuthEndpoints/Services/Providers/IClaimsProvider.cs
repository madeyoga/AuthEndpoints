using System.Security.Claims;

namespace AuthEndpoints.Services.Providers;

public interface IClaimsProvider<TUser> where TUser : class
{
    List<Claim> provideClaims(TUser user);
}
