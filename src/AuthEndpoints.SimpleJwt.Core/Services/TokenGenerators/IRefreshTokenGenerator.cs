using System.Security.Claims;

namespace AuthEndpoints.SimpleJwt.Core.Services;
public interface IRefreshTokenGenerator
{
    string GenerateRefreshToken(ClaimsPrincipal user);
}
