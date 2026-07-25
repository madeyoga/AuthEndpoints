using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.Jwt;

public class RefreshTokenCookieWriter
{
    public static readonly string CookieName = "AuthEndpoints.Jwt.RefreshToken";

    public void Write(HttpContext context, RefreshToken refreshToken, CookieOptions? options = null)
    {
        if (string.IsNullOrEmpty(refreshToken.Token))
        {
            throw new InvalidOperationException("Refresh token raw value is missing; cannot write cookie.");
        }

        context.Response.Cookies.Append(
            CookieName,
            refreshToken.Token,
            options ?? CreateDefaultOptions(context, refreshToken.ExpiresAt));
    }

    public void Delete(HttpContext context)
    {
        context.Response.Cookies.Delete(CookieName, CreateDefaultOptions(context, DateTime.UtcNow));
    }

    private static CookieOptions CreateDefaultOptions(HttpContext context, DateTime expiresAt) => new()
    {
        HttpOnly = true,
        Secure = context.Request.IsHttps,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        Expires = expiresAt
    };
}
