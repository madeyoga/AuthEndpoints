using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// A class for configuring <see cref="SimpleJwtOptions"/>
/// </summary>
public class SimpleJwtOptionsConfigurator : IPostConfigureOptions<SimpleJwtOptions>
{
    public void PostConfigure(string name, SimpleJwtOptions options)
    {
        var accessSigning = options.AccessSigningOptions;

        if (accessSigning.SigningKey == null)
        {
            var secret = LoadOrGenerateSecretKey("keys/authendpoints__access_secret.txt");
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
    }

    /// <summary>
    /// securely generate a random string
    /// </summary>
    /// <param name="length"></param>
    /// <param name="allowedChars"></param>
    /// <returns>a securely generated random string</returns>
    private string GetRandomString(int length, string allowedChars)
    {
        var secret = "";

        for (var i = 0; i < length; i++)
        {
            var randomIndex = RandomNumberGenerator.GetInt32(0, allowedChars.Length);
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
        var allowedChars = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)";
        return GetRandomString(50, allowedChars);
    }

    private string LoadOrGenerateSecretKey(string filepath)
    {
        var directoryName = Path.GetDirectoryName(filepath)!;

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
        var secret = GetRandomSecretKey();

        using var file = File.Create(filepath);
        file.Write(Encoding.UTF8.GetBytes(secret));

        return secret;
    }
}
