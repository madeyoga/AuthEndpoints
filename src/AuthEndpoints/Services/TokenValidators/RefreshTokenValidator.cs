namespace AuthEndpoints.Services;

using AuthEndpoints;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

public class RefreshTokenValidator : ITokenValidator
{
    private readonly TokenValidationParameters validationParameters;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public RefreshTokenValidator(IOptions<AuthEndpointsOptions> options, JwtSecurityTokenHandler tokenHandler)
    {
        validationParameters = options.Value.RefreshTokenValidationParameters!;
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
