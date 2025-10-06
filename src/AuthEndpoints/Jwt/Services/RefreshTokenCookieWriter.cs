using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.Jwt;

public class RefreshTokenCookieWriter
{
    public static readonly string CookieName = "AuthEndpoints.Jwt.RefreshToken";

    public void Write(HttpContext context, RefreshToken refreshToken, CookieOptions? options = null)
    {
        context.Response.Cookies.Append(CookieName, refreshToken.Token, options ?? new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = refreshToken.ExpiresAt
        });
    }
}
