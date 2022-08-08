using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Core.Exceptions;
using AuthEndpoints.Core.Repositories;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Core.Services;

/// <summary>
/// Use this class to validate refresh tokens
/// </summary>
public class RefreshTokenValidator : IRefreshTokenValidator
{
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly TokenValidationParameters _validationParameters;
    private readonly IRefreshTokenRepository _refreshTokenRepository;

    public RefreshTokenValidator(JwtSecurityTokenHandler tokenHandler, IOptions<AuthEndpointsOptions> options, IRefreshTokenRepository repository)
    {
        _tokenHandler = tokenHandler;
        _validationParameters = options.Value.RefreshValidationParameters!;
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
        var refreshToken = await _refreshTokenRepository.GetByTokenAsync(token);

        // if not exists: return invalid validation result.
        if (refreshToken is null)
        {
            return new TokenValidationResult
            {
                IsValid = false,
                Exception = new RefreshTokenNotFoundException("Refresh token might be invalid or expired"),
            };
        }

        // if jwt is invalid: delete token from db? and return validation result.
        var result = await _tokenHandler.ValidateTokenAsync(token, _validationParameters);
        if (!result.IsValid)
        {
            // delete token from db
            // ...
            return result;
        }

        return result;
    }
}
