using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

public class OptionsConfigurator : IPostConfigureOptions<AuthEndpointsOptions>
{
    private readonly ILogger _logger;

    public OptionsConfigurator(ILogger<OptionsConfigurator> logger)
    {
        _logger = logger;
    }

    public void PostConfigure(string name, AuthEndpointsOptions options)
    {
        var accessOptions = options.AccessSigningOptions;
        if (accessOptions.SigningKey == null)
        {
            string secret = GetRandomSecretKey();
            accessOptions.SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            _logger.LogInformation("Access token signing defaults to using 256-bit HMAC signing", DateTime.UtcNow.ToLongTimeString());
        }

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

                _logger.LogInformation("AccessValidationParameters.IssuerSigningKey uses JwtSigningOptions.SigningKey", DateTime.UtcNow.ToLongTimeString());
            }
        }

        var refreshOptions = options.RefreshSigningOptions;

        if (refreshOptions.SigningKey == null)
        {
            string secret = GetRandomSecretKey();
            refreshOptions.SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            _logger.LogInformation("Refresh token signing defaults to using 256-bit HMAC signing", DateTime.UtcNow.ToLongTimeString());
        }

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

    /// <summary>
    /// securely generate a random string
    /// </summary>
    /// <param name="length"></param>
    /// <param name="allowedChars"></param>
    /// <returns>a securely generated random string</returns>
    private string GetRandomString(int length, string allowedChars)
    {
        string secret = "";

        for (int i = 0; i < length; i++)
        {
            int randomIndex = RandomNumberGenerator.GetInt32(0, length);
            secret += allowedChars[randomIndex];
        }

        return secret;
    }

    /// <summary>
    /// Securely generate a 50 character random string.
    /// </summary>
    /// <returns>a securely generated 50 character random string</returns>
    private string GetRandomSecretKey()
    {
        string allowedChars = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)";
        return GetRandomString(50, allowedChars);
    }

    private string LoadOrGenerateSecretKey(string path)
    {
        // Check if file exist
        // if exist, try to load the secret from the file.
        // If not exist, generate a new secret key then save it to a new file.
        return GetRandomSecretKey();
    }
}
