using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services;

/// <summary>
/// Use <see cref="DefaultJwtValidator"/> to validate a jwt
/// </summary>
public class DefaultJwtValidator : IJwtValidator
{
    private readonly JwtSecurityTokenHandler tokenHandler;

    public DefaultJwtValidator(JwtSecurityTokenHandler tokenHandler)
    {
        this.tokenHandler = tokenHandler;
    }

    /// <summary>
    /// Read jwt from the given string
    /// </summary>
    /// <param name="token"></param>
    /// <returns>An instance of JwtSecurityToken</returns>
    public JwtSecurityToken ReadJwtToken(string token)
    {
        return tokenHandler.ReadJwtToken(token);
    }

    /// <summary>
    /// Use this method to validate a jwt
    /// </summary>
    /// <param name="token"></param>
    /// <param name="validationParameters"></param>
    /// <returns>a boolean, return true if valid</returns>
    public bool Validate(string token, TokenValidationParameters validationParameters)
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

    public async Task<bool> ValidateAsync(string token, TokenValidationParameters validationParameters)
    {
        var result = await tokenHandler.ValidateTokenAsync(token, validationParameters);
        return result.IsValid;
    }
}