using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Issues and reads refresh tokens for the configured <see cref="RefreshTokenTransport"/>.
/// </summary>
internal static class JwtRefreshDelivery
{
    public static JwtSessionOptions Session(HttpContext httpContext)
    {
        return httpContext.RequestServices.GetService<IOptions<JwtSessionOptions>>()?.Value
            ?? new JwtSessionOptions();
    }

    public static JwtSessionOptions Session(IServiceProvider services)
    {
        return services.GetService<IOptions<JwtSessionOptions>>()?.Value
            ?? new JwtSessionOptions();
    }

    public static bool IsBody(JwtSessionOptions options)
        => options.RefreshTokenTransport == RefreshTokenTransport.Body;

    public static void WriteCookie(
        HttpContext httpContext,
        RefreshTokenCookieWriter writer,
        RefreshToken refreshToken,
        JwtSessionOptions options)
    {
        if (!IsBody(options))
        {
            writer.Write(httpContext, refreshToken);
        }
    }

    public static void DeleteCookie(
        HttpContext httpContext,
        RefreshTokenCookieWriter writer,
        JwtSessionOptions options)
    {
        if (!IsBody(options))
        {
            writer.Delete(httpContext);
        }
    }

    public static void ApplyBody(SimpleJwtTokenResponse response, RefreshToken refreshToken, JwtSessionOptions options)
    {
        if (IsBody(options))
        {
            response.RefreshToken = refreshToken.Token;
        }
    }

    public static async Task<string?> ReadPresentedTokenAsync(HttpContext httpContext, JwtSessionOptions options)
    {
        if (!IsBody(options))
        {
            return httpContext.Request.Cookies.TryGetValue(RefreshTokenCookieWriter.CookieName, out var cookie)
                ? cookie
                : null;
        }

        if (httpContext.Request.ContentLength == 0)
        {
            return null;
        }

        try
        {
            var body = await httpContext.Request.ReadFromJsonAsync<SimpleJwtRefreshTokenRequest>();
            return string.IsNullOrWhiteSpace(body?.RefreshToken) ? null : body.RefreshToken;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            // No JSON content type, or an empty body the formatter rejects.
            return null;
        }
    }
}
