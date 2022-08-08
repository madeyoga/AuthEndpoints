using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Core.Services;

public interface IRefreshTokenValidator
{
    Task<TokenValidationResult> ValidateRefreshTokenAsync(string token);
}
