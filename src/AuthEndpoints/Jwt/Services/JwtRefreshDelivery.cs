using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

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

    public static async Task<PresentedRefreshToken> ReadPresentedTokenAsync(HttpContext httpContext, JwtSessionOptions options)
    {
        if (!IsBody(options))
        {
            var cookie = httpContext.Request.Cookies.TryGetValue(RefreshTokenCookieWriter.CookieName, out var value)
                ? value
                : null;
            return new PresentedRefreshToken(cookie, UnsupportedMediaType: false);
        }

        if (httpContext.Request.ContentLength == 0)
        {
            return new PresentedRefreshToken(null, UnsupportedMediaType: false);
        }

        if (!httpContext.Request.HasJsonContentType())
        {
            return new PresentedRefreshToken(null, UnsupportedMediaType: true);
        }

        try
        {
            var body = await httpContext.Request.ReadFromJsonAsync<SimpleJwtRefreshTokenRequest>();
            var token = string.IsNullOrWhiteSpace(body?.RefreshToken) ? null : body.RefreshToken;
            return new PresentedRefreshToken(token, UnsupportedMediaType: false);
        }
        catch (JsonException)
        {
            return new PresentedRefreshToken(null, UnsupportedMediaType: false);
        }
    }
}

internal readonly record struct PresentedRefreshToken(string? Value, bool UnsupportedMediaType);
