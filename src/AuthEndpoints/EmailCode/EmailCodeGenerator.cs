using System.Buffers.Binary;
using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;

namespace AuthEndpoints.EmailCode;

internal static class EmailCodeGenerator
{
    public static string CreateCode(int length)
    {
        if (length is < EmailCodeOptionsValidator.MinimumCodeLength or > EmailCodeOptionsValidator.MaximumCodeLength)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        long value = NextBelow(Pow10(length));
        return FormatCode(value, length);
    }

    public static string CreateLinkToken()
    {
        return Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
    }

    internal static string FormatCode(long value, int length)
    {
        return value.ToString(CultureInfo.InvariantCulture).PadLeft(length, '0');
    }

    private static long Pow10(int length)
    {
        long value = 1;
        for (var i = 0; i < length; i++)
        {
            value *= 10;
        }

        return value;
    }

    private static long NextBelow(long exclusive)
    {
        if (exclusive <= int.MaxValue)
        {
            return RandomNumberGenerator.GetInt32(0, (int)exclusive);
        }

        return NextInt64(exclusive);
    }

    private static long NextInt64(long exclusive)
    {
        ulong limit = (ulong)exclusive;
        ulong remainder = ((ulong.MaxValue % limit) + 1) % limit;
        ulong maxInclusive = ulong.MaxValue - remainder;
        Span<byte> bytes = stackalloc byte[8];
        while (true)
        {
            RandomNumberGenerator.Fill(bytes);
            ulong sample = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
            if (sample <= maxInclusive)
            {
                return (long)(sample % limit);
            }
        }
    }
}
