namespace AuthEndpoints.Services;

using AuthEndpoints;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

/// <summary>
/// Use this class to validate a refresh token
/// </summary>
public class RefreshTokenValidator : ITokenValidator
{
    private readonly TokenValidationParameters validationParameters;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public RefreshTokenValidator(IOptions<AuthEndpointsOptions> options, JwtSecurityTokenHandler tokenHandler)
    {
        validationParameters = options.Value.RefreshTokenValidationParameters!;
        this.tokenHandler = tokenHandler;
    }

    /// <summary>
    /// Use this method to convert string jwt to <see cref="JwtSecurityToken"/>
    /// </summary>
    /// <param name="token"></param>
    /// <returns>An instance of <see cref="JwtSecurityToken"/></returns>
    public JwtSecurityToken ReadJwtToken(string token)
    {
        return tokenHandler.ReadJwtToken(token);
    }

    /// <summary>
    /// Use this method to validate a refresh token. Token may be expired or invalid.
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
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
