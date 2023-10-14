using System.Security.Claims;

namespace AuthEndpoints.SimpleJwt;
public interface IRefreshTokenService
{
    string GenerateRefreshToken(ClaimsPrincipal user);
    ClaimsPrincipal GetTokenClaimsAsync();
}
