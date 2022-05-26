using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

public class OptionsConfigurator : IPostConfigureOptions<AuthEndpointsOptions>
{
    public void PostConfigure(string name, AuthEndpointsOptions options)
    {
        var accessOptions = options.AccessSigningOptions!;
        if (accessOptions.Algorithm!.StartsWith("HS"))
        {
            if (options.AccessValidationParameters == null)
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
            else
            {
                options.AccessValidationParameters.IssuerSigningKey = accessOptions.SigningKey;
            }
        }

        var refreshOptions = options.RefreshSigningOptions!;
        if (refreshOptions.Algorithm!.StartsWith("HS"))
        {
            if (options.RefreshValidationParameters == null)
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
            else
            {
                options.RefreshValidationParameters.IssuerSigningKey = refreshOptions.SigningKey;
            }
        }
    }
}
