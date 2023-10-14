using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt;

public interface IRefreshTokenValidator
{
    Task<TokenValidationResult> ValidateRefreshTokenAsync(string token);
}
