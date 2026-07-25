using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace AuthEndpoints.ReAuth;

internal sealed class ReAuthTokenService
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;

    public ReAuthTokenService(IDataProtectionProvider dataProtectionProvider, TimeProvider timeProvider)
    {
        _protector = dataProtectionProvider.CreateProtector("AuthEndpoints.ReAuth.Bearer.v1");
        _timeProvider = timeProvider;
    }

    public string CreateToken(IEnumerable<Claim> claims)
    {
        var expires = _timeProvider.GetUtcNow().Add(Lifetime);
        var payload = new ReAuthTokenPayload(
            expires.ToUnixTimeSeconds(),
            claims.Select(c => new ReAuthClaim(c.Type, c.Value)).ToArray());

        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        return Base64UrlEncode(_protector.Protect(bytes));
    }

    public ClaimsPrincipal? Unprotect(string token)
    {
        try
        {
            var bytes = _protector.Unprotect(Base64UrlDecode(token));
            var payload = JsonSerializer.Deserialize<ReAuthTokenPayload>(bytes);
            if (payload is null)
            {
                return null;
            }

            var expires = DateTimeOffset.FromUnixTimeSeconds(payload.ExpiresUnix);
            if (_timeProvider.GetUtcNow() >= expires)
            {
                return null;
            }

            var identity = new ClaimsIdentity(
                payload.Claims.Select(c => new Claim(c.Type, c.Value)),
                AuthEndpoints.Identity.AuthEndpointsConstants.ReAuthBearerScheme);

            return new ClaimsPrincipal(identity);
        }
        catch
        {
            return null;
        }
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        return Convert.FromBase64String(padded);
    }

    private sealed record ReAuthTokenPayload(long ExpiresUnix, ReAuthClaim[] Claims);
    private sealed record ReAuthClaim(string Type, string Value);
}
