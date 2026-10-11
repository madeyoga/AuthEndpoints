using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using AuthEndpoints.EmailCode;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

public class EmailCodeCoreTests
{
    [Theory]
    [InlineData(6)]
    [InlineData(8)]
    [InlineData(10)]
    public void CreateCode_HasExactLengthAndDigits(int length)
    {
        for (var i = 0; i < 40; i++)
        {
            string code = EmailCodeGenerator.CreateCode(length);
            Assert.Equal(length, code.Length);
            Assert.Matches("^[0-9]+$", code);
        }
    }

    [Fact]
    public void CreateCode_KeepsLeadingZeros()
    {
        var sawLeadingZero = false;
        for (var i = 0; i < 200 && !sawLeadingZero; i++)
        {
            sawLeadingZero = EmailCodeGenerator.CreateCode(6).StartsWith('0');
        }

        Assert.True(sawLeadingZero);
    }

    [Fact]
    public void FormatCode_KeepsLeadingZeros()
    {
        Assert.Equal("042317", EmailCodeGenerator.FormatCode(42317, 6));
        Assert.Equal("000000", EmailCodeGenerator.FormatCode(0, 6));
        Assert.Equal("0000000042", EmailCodeGenerator.FormatCode(42, 10));
    }

    [Fact]
    public void CreateLinkToken_Is32BytesAndRoundTripsBase64Url()
    {
        string token = EmailCodeGenerator.CreateLinkToken();
        byte[] bytes = Base64Url.DecodeFromChars(token);
        Assert.Equal(32, bytes.Length);
        Assert.Equal(token, Base64Url.EncodeToString(bytes));
    }

    [Fact]
    public void CodeHash_MatchesRightCode_RejectsWrongCode_AndOtherRowId()
    {
        const string id = "row-1";
        const string code = "042317";
        string hash = EmailCodeHasher.HashCode(id, code);
        string expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(id + ":" + code)));

        Assert.Equal(expected, hash);
        Assert.NotEqual(code, hash);
        Assert.True(EmailCodeHasher.CodeMatches(id, code, hash));
        Assert.False(EmailCodeHasher.CodeMatches(id, "042318", hash));
        Assert.False(EmailCodeHasher.CodeMatches(id, "42317", hash));
        Assert.False(EmailCodeHasher.CodeMatches("row-2", code, hash));
        Assert.NotEqual(hash, EmailCodeHasher.HashCode("row-2", code));
    }

    [Fact]
    public void LinkTokenHash_IsSha256OfTheToken()
    {
        const string token = "abcdefghijklmnopqrstuvwxyz012345";
        string hash = EmailCodeHasher.HashLinkToken(token);
        string expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        Assert.Equal(expected, hash);
        Assert.NotEqual(token, hash);
    }

    [Fact]
    public void EmailHash_TrimsAndIgnoresCase()
    {
        var normalizer = new UpperInvariantLookupNormalizer();
        string Hash(string email) => EmailCodeHasher.HashEmail(normalizer.NormalizeEmail(email.Trim())!);

        string left = Hash("A@X.com ");
        string right = Hash("a@x.com");
        string other = Hash("b@x.com");

        Assert.Equal(left, right);
        Assert.NotEqual(left, other);
        Assert.Equal("A@X.COM", normalizer.NormalizeEmail("A@X.com ".Trim()));
        Assert.Equal("A@X.COM", normalizer.NormalizeEmail("a@x.com".Trim()));
    }
}
