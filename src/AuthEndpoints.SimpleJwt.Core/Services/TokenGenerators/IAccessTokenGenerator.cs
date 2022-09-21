using System.Security.Claims;

namespace AuthEndpoints.SimpleJwt.Core.Services;

public interface IAccessTokenGenerator
{
    string GenerateAccessToken(ClaimsPrincipal user);
}
