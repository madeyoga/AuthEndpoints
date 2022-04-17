using AuthEndpoints.Jwt.Models.Configurations;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthEndpoints.Jwt.Services.TokenValidators;

internal class AccessTokenValidator : ITokenValidator
{
    private readonly TokenValidationParameters validationParameters;
    private readonly JwtSecurityTokenHandler tokenHandler;

    public AccessTokenValidator(AuthenticationConfiguration authConfig, JwtSecurityTokenHandler tokenHandler)
    {
        validationParameters = new TokenValidationParameters()
        {
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authConfig.AccessTokenSecret!)),
            ValidIssuer = authConfig.Issuer,
            ValidAudience = authConfig.Audience,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ClockSkew = TimeSpan.Zero,
        };

        this.tokenHandler = tokenHandler;
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
}
