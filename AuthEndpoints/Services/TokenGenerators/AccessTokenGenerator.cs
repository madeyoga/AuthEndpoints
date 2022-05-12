using System.Security.Cryptography;

namespace AuthEndpoints.Services.TokenGenerators;
internal class AccessTokenGenerator<TUser> : ITokenGenerator<TUser>
{
    public string GenerateToken(TUser user)
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(20))!;
    }
}
