using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

public class OptionsConfigurator : IPostConfigureOptions<AuthEndpointsOptions>
{
    public void PostConfigure(string name, AuthEndpointsOptions options)
    {
        var accessSigning = options.AccessSigningOptions;

        if (accessSigning.SigningKey == null)
        {
            string secret = LoadOrGenerateSecretKey("keys/authendpoints__access_secret.txt");
            accessSigning.SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            accessSigning.Algorithm = SecurityAlgorithms.HmacSha256;
        }

        if (accessSigning.Algorithm.StartsWith("HS"))
        {
            if (options.AccessValidationParameters == null)
            {
                options.AccessValidationParameters = new TokenValidationParameters()
                {
                    IssuerSigningKey = accessSigning.SigningKey,
                    ValidIssuer = options.Issuer,
                    ValidAudience = options.Audience,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                };
            }
            else
            {
                options.AccessValidationParameters.IssuerSigningKey = accessSigning.SigningKey;
            }
        }

        var refreshSigning = options.RefreshSigningOptions;

        if (refreshSigning.SigningKey == null)
        {
            string secret = LoadOrGenerateSecretKey("keys/authendpoints__refresh_secret.txt");
            refreshSigning.SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            refreshSigning.Algorithm = SecurityAlgorithms.HmacSha256;
        }

        if (refreshSigning.Algorithm.StartsWith("HS"))
        {
            if (options.RefreshValidationParameters == null)
            {
                options.RefreshValidationParameters = new TokenValidationParameters()
                {
                    IssuerSigningKey = refreshSigning.SigningKey,
                    ValidIssuer = options.Issuer,
                    ValidAudience = options.Audience,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                };
            }
            else
            {
                options.RefreshValidationParameters.IssuerSigningKey = refreshSigning.SigningKey;
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

    private string LoadOrGenerateSecretKey(string filepath)
    {
        string directoryName = Path.GetDirectoryName(filepath)!;

        if (!Directory.Exists(directoryName))
        {
            Directory.CreateDirectory(directoryName);
        }

        // if file exists
        if (File.Exists(filepath))
        {
            // load
            return File.ReadAllText(filepath);
        }

        // file not exist, generate new secret then save it to a new file
        string secret = GetRandomSecretKey();

        using var file = File.Create(filepath);
        file.Write(Encoding.UTF8.GetBytes(secret));

        return secret;
    }
}
