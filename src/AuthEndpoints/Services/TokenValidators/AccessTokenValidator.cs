using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Services;

internal class AccessTokenValidator : ITokenValidator
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
