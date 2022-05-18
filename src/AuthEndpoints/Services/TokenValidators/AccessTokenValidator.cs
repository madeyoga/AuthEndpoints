using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services;

/// <summary>
/// Use this class to validate an access jwt
/// </summary>
internal class AccessTokenValidator : IAccessTokenValidator
{
    private readonly TokenValidationParameters validationParameters;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public AccessTokenValidator(IOptions<AuthEndpointsOptions> options, JwtSecurityTokenHandler tokenHandler)
    {
        validationParameters = options.Value.AccessTokenValidationParameters!;

        this.tokenHandler = tokenHandler;
    }

    public JwtSecurityToken ReadJwtToken(string token)
    {
        return tokenHandler.ReadJwtToken(token);
    }

    /// <summary>
    /// Use this method to validate an access token
    /// </summary>
    /// <param name="token"></param>
    /// <returns>a boolean. True if valid token else false. Token may be expired or invalid.</returns>
    public bool Validate(string token)
    {
        try
        {
            tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
        }
        catch
        {
            return false;
        }

        return true;
    }

    public async Task<bool> ValidateAsync(string token)
    {
        var result = await tokenHandler.ValidateTokenAsync(token, validationParameters);
        return result.IsValid;
    }
}
