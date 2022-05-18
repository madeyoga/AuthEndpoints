using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="ITokenValidator"/> to define your token validator
/// </summary>
public interface ITokenValidator
{
    bool Validate(string token);
    Task<bool> ValidateAsync(string token);
    JwtSecurityToken ReadJwtToken(string token);
}
