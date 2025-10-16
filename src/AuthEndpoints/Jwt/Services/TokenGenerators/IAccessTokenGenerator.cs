using System.Security.Claims;

namespace AuthEndpoints.Jwt;

public interface IAccessTokenGenerator
{
    string GenerateAccessToken(ClaimsPrincipal user);
}
