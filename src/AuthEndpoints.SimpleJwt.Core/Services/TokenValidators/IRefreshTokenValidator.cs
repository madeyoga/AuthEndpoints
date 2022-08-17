using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt.Core.Services;

public interface IRefreshTokenValidator
{
    Task<TokenValidationResult> ValidateRefreshTokenAsync(string token);
}
