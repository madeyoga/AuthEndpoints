using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services;

public interface IJwtValidator
{
    JwtSecurityToken ReadJwtToken(string token);
    bool Validate(string token, TokenValidationParameters validationParameters);
    Task<bool> ValidateAsync(string token, TokenValidationParameters validationParameters);
}
