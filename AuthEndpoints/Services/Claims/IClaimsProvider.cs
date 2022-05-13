using System.Security.Claims;

namespace AuthEndpoints.Services.Claims;

public interface IClaimsProvider<TUser> where TUser : class
{
    List<Claim> provideAccessTokenClaims(TUser user);
    List<Claim> provideRefreshTokenClaims(TUser user);
}
