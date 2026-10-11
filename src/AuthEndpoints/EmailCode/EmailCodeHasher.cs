using System.Security.Cryptography;
using System.Text;

namespace AuthEndpoints.EmailCode;

internal static class EmailCodeHasher
{
    public static string NormalizeEmail(string email)
    {
        ArgumentNullException.ThrowIfNull(email);
        return email.Trim().Normalize(NormalizationForm.FormC).ToUpperInvariant();
    }

    public static string HashEmail(string normalizedEmail)
    {
        return Hash(normalizedEmail);
    }

    public static string HashCode(string id, string code)
    {
        return Hash(id + ":" + code);
    }

    public static string HashLinkToken(string token)
    {
        return Hash(token);
    }

    public static bool CodeMatches(string id, string submittedCode, string storedCodeHash)
    {
        byte[] computed = SHA256.HashData(Encoding.UTF8.GetBytes(id + ":" + submittedCode));
        byte[] stored = Convert.FromHexString(storedCodeHash);
        return CryptographicOperations.FixedTimeEquals(computed, stored);
    }

    private static string Hash(string value)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes);
    }
}
