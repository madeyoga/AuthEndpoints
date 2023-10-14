using System.Security.Claims;

namespace AuthEndpoints.SimpleJwt;

public interface IAccessTokenGenerator
{
    string GenerateAccessToken(ClaimsPrincipal user);
}
