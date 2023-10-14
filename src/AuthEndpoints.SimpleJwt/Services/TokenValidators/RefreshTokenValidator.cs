using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// Use this class to validate refresh tokens
/// </summary>
public class RefreshTokenValidator : IRefreshTokenValidator
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;

    public RefreshTokenValidator(IRefreshTokenRepository repository)
    {
        _refreshTokenRepository = repository;
    }

    /// <summary>
    /// Validate a refresh token
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public async Task<TokenValidationResult> ValidateRefreshTokenAsync(string token)
    {
        // Check if token exists in the database.
        return new TokenValidationResult()
        {
            IsValid = await _refreshTokenRepository.GetByTokenAsync(token) is not null,
        };
    }
}
