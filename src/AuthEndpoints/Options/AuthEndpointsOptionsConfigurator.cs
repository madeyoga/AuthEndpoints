using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AuthEndpoints;

internal class AuthEndpointsOptionsConfigurator : IPostConfigureOptions<AuthEndpointsOptions>
{
    public void Configure(AuthEndpointsOptions options)
    {
        if (options.AccessTokenValidationParameters == null)
        {
            options.AccessTokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.AccessTokenSecret!)),
                ValidIssuer = options.Issuer,
                ValidAudience = options.Audience,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
            };
        }

        if (options.RefreshTokenValidationParameters == null)
        {
            options.RefreshTokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.RefreshTokenSecret!)),
                ValidIssuer = options.Issuer,
                ValidAudience = options.Audience,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
            };
        }
    }

    public void PostConfigure(string name, AuthEndpointsOptions options)
    {
        if (options.AccessTokenValidationParameters == null)
        {
            options.AccessTokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.AccessTokenSecret!)),
                ValidIssuer = options.Issuer,
                ValidAudience = options.Audience,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
            };
        }

        if (options.RefreshTokenValidationParameters == null)
        {
            options.RefreshTokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.RefreshTokenSecret!)),
                ValidIssuer = options.Issuer,
                ValidAudience = options.Audience,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
            };
        }
    }
}
