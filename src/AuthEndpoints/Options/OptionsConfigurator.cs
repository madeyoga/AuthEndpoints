using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Options;

public class OptionsConfigurator : IPostConfigureOptions<AuthEndpointsOptions>
{
    public void PostConfigure(string name, AuthEndpointsOptions options)
    {
        var accessOptions = options.AccessSigningOptions!;
        if (accessOptions.Algorithm!.StartsWith("HS") && options.AccessValidationParameters == null)
        {
            options.AccessValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = accessOptions.SigningKey,
                ValidIssuer = options.Issuer,
                ValidAudience = options.Audience,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
            };
        }

        var refreshOptions = options.RefreshSigningOptions!;
        if (refreshOptions.Algorithm!.StartsWith("HS") && options.RefreshValidationParameters == null)
        {
            options.RefreshValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = refreshOptions.SigningKey,
                ValidIssuer = options.Issuer,
                ValidAudience = options.Audience,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
            };
        }
    }
}
