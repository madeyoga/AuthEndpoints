using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services.TokenValidators;

public interface ITokenValidator
{
    bool Validate(string token);
    Task<bool> ValidateAsync(string token);
    JwtSecurityToken ReadJwtToken(string token);
}
