using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Writes and deletes the HTTP-only refresh token cookie for JWT sessions.
/// </summary>
public class RefreshTokenCookieWriter
{
    /// <summary>
    /// Default name of the refresh token cookie (<c>"AuthEndpoints.Jwt.RefreshToken"</c>).
    /// </summary>
    public static readonly string CookieName = "AuthEndpoints.Jwt.RefreshToken";

    /// <summary>
    /// Appends the refresh token cookie to the HTTP response using <see cref="CookieName"/>.
    /// When <paramref name="options"/> is <see langword="null"/>, default settings are applied:
    /// <see cref="CookieOptions.HttpOnly"/> is <see langword="true"/>,
    /// <see cref="CookieOptions.Secure"/> is <see langword="true"/> when the request is HTTPS,
    /// <see cref="CookieOptions.SameSite"/> is <see cref="SameSiteMode.Strict"/>,
    /// <see cref="CookieOptions.Path"/> is <c>"/"</c>, and
    /// <see cref="CookieOptions.Expires"/> matches <see cref="RefreshToken.ExpiresAt"/>.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/> whose response receives the cookie.</param>
    /// <param name="refreshToken">The refresh token containing the raw token value and expiration timestamp.</param>
    /// <param name="options">Optional custom cookie settings. When <see langword="null"/>, default options are used.</param>
    /// <exception cref="InvalidOperationException">Thrown when <see cref="RefreshToken.Token"/> is null or empty.</exception>
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

    /// <summary>
    /// Deletes the refresh token cookie (<see cref="CookieName"/>) from the HTTP response using matching default cookie options expired at the current time.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/> whose response cookie is deleted.</param>
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
