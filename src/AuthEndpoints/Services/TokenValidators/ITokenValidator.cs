using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services;

public interface ITokenValidator
{
    bool Validate(string token);
    Task<bool> ValidateAsync(string token);
    JwtSecurityToken ReadJwtToken(string token);
}
