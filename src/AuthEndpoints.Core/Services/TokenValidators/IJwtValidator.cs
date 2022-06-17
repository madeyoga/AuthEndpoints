using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IJwtValidator"/> to define your jwt validator
/// </summary>
public interface IJwtValidator
{
    JwtSecurityToken ReadJwtToken(string token);
    bool Validate(string token, TokenValidationParameters validationParameters);
    Task<bool> ValidateAsync(string token, TokenValidationParameters validationParameters);
}