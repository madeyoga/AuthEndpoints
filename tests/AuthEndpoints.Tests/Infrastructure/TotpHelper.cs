using System.Security.Cryptography;
using System.Text;

namespace AuthEndpoints.Tests;

/// <summary>
/// Minimal RFC 6238 TOTP helper matching ASP.NET Identity authenticator verification
/// (Base32 shared key, HMAC-SHA1, 30s step, 6 digits).
/// </summary>
internal static class TotpHelper
{
    public static string GenerateCode(string base32Key, DateTimeOffset? utcNow = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(base32Key);
        var key = Base32Decode(base32Key);
        var timestep = (utcNow ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / 30;
        return ComputeTotp(key, timestep);
    }

    private static string ComputeTotp(byte[] key, long timestep)
    {
        Span<byte> timestepBytes = stackalloc byte[8];
        for (var i = 7; i >= 0; i--)
        {
            timestepBytes[i] = (byte)(timestep & 0xff);
            timestep >>= 8;
        }

        Span<byte> hash = stackalloc byte[HMACSHA1.HashSizeInBytes];
        HMACSHA1.HashData(key, timestepBytes, hash);

        var offset = hash[^1] & 0x0f;
        var binary =
            ((hash[offset] & 0x7f) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];

        var code = binary % 1_000_000;
        return code.ToString("D6");
    }

    private static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var trimmed = input.Trim().TrimEnd('=').Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
        var bits = new StringBuilder(trimmed.Length * 5);

        foreach (var c in trimmed)
        {
            var value = alphabet.IndexOf(c);
            if (value < 0)
            {
                throw new FormatException($"Invalid Base32 character '{c}'.");
            }

            bits.Append(Convert.ToString(value, 2).PadLeft(5, '0'));
        }

        var bitString = bits.ToString();
        var byteCount = bitString.Length / 8;
        var bytes = new byte[byteCount];
        for (var i = 0; i < byteCount; i++)
        {
            bytes[i] = Convert.ToByte(bitString.Substring(i * 8, 8), 2);
        }

        return bytes;
    }
}
