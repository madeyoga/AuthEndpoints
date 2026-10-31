using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Sessions;

/// <summary>
/// Hooks the Identity application cookie: sign-in creates (or, for a refreshed sign-in, keeps)
/// a session record; each request checks it; sign-out and stamp rejection end it.
/// </summary>
internal sealed class ActiveSessionCookieEvents : IPostConfigureOptions<CookieAuthenticationOptions>
{
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        if (!string.Equals(name, IdentityConstants.ApplicationScheme, StringComparison.Ordinal))
        {
            return;
        }

        var events = options.Events ??= new CookieAuthenticationEvents();
        var cookie = options;
        var signingIn = events.OnSigningIn;
        var validate = events.OnValidatePrincipal;
        var signingOut = events.OnSigningOut;

        events.OnSigningIn = async context =>
        {
            await SigningInAsync(context, cookie);
            await signingIn(context);
        };
        events.OnValidatePrincipal = async context =>
        {
            await validate(context);
            await ValidateAsync(context, cookie);
        };
        events.OnSigningOut = async context =>
        {
            await SigningOutAsync(context);
            await signingOut(context);
        };
    }

    private static async Task SigningInAsync(CookieSigningInContext context, CookieAuthenticationOptions cookie)
    {
        var principal = context.Principal;
        if (principal is null)
        {
            return;
        }

        var services = context.HttpContext.RequestServices;
        var identityOptions = services.GetRequiredService<IOptions<IdentityOptions>>().Value;
        var userId = principal.FindFirst(identityOptions.ClaimsIdentity.UserIdClaimType)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return;
        }

        var stamp = principal.FindFirst(identityOptions.ClaimsIdentity.SecurityStampClaimType)?.Value ?? string.Empty;
        var time = services.GetRequiredService<TimeProvider>();
        var expiresAt = context.Properties.ExpiresUtc?.UtcDateTime
            ?? time.GetUtcNow().UtcDateTime.Add(cookie.ExpireTimeSpan);
        var store = services.GetRequiredService<IActiveSessionStore>();

        // RefreshSignInAsync keeps the cookie's AuthenticationProperties, so a refreshed sign-in
        // (password change, linking) keeps its session. A fresh sign-in starts with new properties.
        if (context.Properties.Items.TryGetValue(ActiveSessionRequest.PropertiesKey, out var existingId)
            && !string.IsNullOrEmpty(existingId))
        {
            var existing = await store.FindAsync(existingId);
            if (existing is not null
                && existing.RevokedAt is null
                && string.Equals(existing.UserId, userId, StringComparison.Ordinal))
            {
                await store.UpdateStampAsync(existingId, stamp, expiresAt);
                ActiveSessionRequest.SetClaim(principal, existingId);
                return;
            }
        }

        var id = ActiveSessionRequest.NewId();
        await store.CreateAsync(
            id,
            userId,
            context.HttpContext.Request.Headers.UserAgent.ToString(),
            stamp,
            expiresAt);
        context.Properties.Items[ActiveSessionRequest.PropertiesKey] = id;
        ActiveSessionRequest.SetClaim(principal, id);
    }

    private static async Task ValidateAsync(CookieValidatePrincipalContext context, CookieAuthenticationOptions cookie)
    {
        var services = context.HttpContext.RequestServices;
        var store = services.GetRequiredService<IActiveSessionStore>();
        context.Properties.Items.TryGetValue(ActiveSessionRequest.PropertiesKey, out var id);

        if (context.Principal is null)
        {
            // The security stamp check rejected the cookie: that session has ended.
            if (!string.IsNullOrEmpty(id))
            {
                await store.EndAsync([id]);
            }

            return;
        }

        var identityOptions = services.GetRequiredService<IOptions<IdentityOptions>>().Value;
        var userId = context.Principal.FindFirst(identityOptions.ClaimsIdentity.UserIdClaimType)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return;
        }

        var time = services.GetRequiredService<TimeProvider>();
        var now = time.GetUtcNow().UtcDateTime;
        DateTime? slidingExpiry = cookie.SlidingExpiration ? now.Add(cookie.ExpireTimeSpan) : null;

        if (string.IsNullOrEmpty(id))
        {
            // Cookie issued before sessions were turned on: adopt it.
            id = ActiveSessionRequest.NewId();
            var stamp = context.Principal.FindFirst(identityOptions.ClaimsIdentity.SecurityStampClaimType)?.Value ?? string.Empty;
            await store.CreateAsync(
                id,
                userId,
                context.HttpContext.Request.Headers.UserAgent.ToString(),
                stamp,
                context.Properties.ExpiresUtc?.UtcDateTime ?? now.Add(cookie.ExpireTimeSpan));
            context.Properties.Items[ActiveSessionRequest.PropertiesKey] = id;
            ActiveSessionRequest.SetClaim(context.Principal, id);
            context.ShouldRenew = true;
            return;
        }

        var session = await store.FindAsync(id);
        if (session is null
            || session.RevokedAt is not null
            || ActiveSessionStore.AsUtc(session.ExpiresAt) <= now
            || !string.Equals(session.UserId, userId, StringComparison.Ordinal))
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(context.Scheme.Name);
            return;
        }

        if (!string.Equals(ActiveSessionRequest.Current(context.Principal), id, StringComparison.Ordinal))
        {
            ActiveSessionRequest.SetClaim(context.Principal, id);
        }

        await store.TouchAsync(session, slidingExpiry);
    }

    private static async Task SigningOutAsync(CookieSigningOutContext context)
    {
        var id = ActiveSessionRequest.Current(context.HttpContext.User);
        if (id is null)
        {
            return;
        }

        var store = context.HttpContext.RequestServices.GetRequiredService<IActiveSessionStore>();
        await store.EndAsync([id]);
    }
}
