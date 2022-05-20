using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services;

public class DefaultJwtValidator : IJwtValidator
{
    private readonly JwtSecurityTokenHandler tokenHandler;

    public DefaultJwtValidator(JwtSecurityTokenHandler tokenHandler)
    {
        this.tokenHandler = tokenHandler;
    }

    public JwtSecurityToken ReadJwtToken(string token)
    {
        return tokenHandler.ReadJwtToken(token);
    }

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
