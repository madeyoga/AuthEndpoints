using System.Security.Cryptography;

namespace AuthEndpoints.TokenAuth.Tests.Web.Services;

/// <summary>
/// Use this class to create an authtoken
/// </summary>
public class AuthTokenGenerator
{
    private readonly string _allowedCharacters = "abcdefghijklmnopqrstuvwxyz0123456789";

    private string getRandomString(int length, string allowedChars)
    {
        var secret = "";

        for (var i = 0; i < length; i++)
        {
            int randomIndex = RandomNumberGenerator.GetInt32(0, allowedChars.Length);
            secret += allowedChars[randomIndex];
        }

        return secret;
    }

    /// <summary>
    /// Securely generate a 40characters random string
    /// </summary>
    /// <param name="length"></param>
    /// <param name="allowedChars"></param>
    /// <returns>a securely generated random string</returns>
    public Task<string> GenerateToken()
    {
        return Task.FromResult(getRandomString(40, _allowedCharacters));
    }
}
