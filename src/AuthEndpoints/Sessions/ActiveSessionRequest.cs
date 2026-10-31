using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.Sessions;

internal static class ActiveSessionRequest
{
    /// <summary>Claim on the cookie principal and in JWT access tokens that names the session.</summary>
    public const string ClaimType = "ae_sid";

    /// <summary>Cookie <c>AuthenticationProperties.Items</c> key. Survives <c>RefreshSignInAsync</c>.</summary>
    public const string PropertiesKey = ".AuthEndpoints.SessionId";

    private static readonly object ItemsKey = new();

    public static string NewId() => Guid.NewGuid().ToString("N");

    /// <summary>
    /// The session this request signs in or refreshes. The access token and the refresh token
    /// for one sign-in are written in either order, so whichever runs first picks the id.
    /// </summary>
    public static string GetOrAllocate(HttpContext? context)
    {
        if (context is null)
        {
            return NewId();
        }

        if (context.Items.TryGetValue(ItemsKey, out var value) && value is string existing)
        {
            return existing;
        }

        var id = NewId();
        context.Items[ItemsKey] = id;
        return id;
    }

    public static void Set(HttpContext? context, string sessionId)
    {
        if (context is not null)
        {
            context.Items[ItemsKey] = sessionId;
        }
    }

    public static string? Current(ClaimsPrincipal? principal)
    {
        var value = principal?.FindFirst(ClaimType)?.Value;
        return string.IsNullOrEmpty(value) ? null : value;
    }

    public static void SetClaim(ClaimsPrincipal principal, string sessionId)
    {
        foreach (var identity in principal.Identities)
        {
            foreach (var claim in identity.FindAll(ClaimType).ToList())
            {
                identity.TryRemoveClaim(claim);
            }
        }

        var target = principal.Identities.FirstOrDefault(i => i.IsAuthenticated) ?? principal.Identities.FirstOrDefault();
        target?.AddClaim(new Claim(ClaimType, sessionId));
    }
}
