using System.ComponentModel;
using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>A pending consent request, as the consent page shows it.</summary>
public sealed record OAuthPendingRequest(
    Guid Id,
    string UserId,
    string ClientId,
    string ClientName,
    string RedirectUri,
    string RedirectHost,
    IReadOnlyList<string> Scopes,
    string Resource,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt)
{
    /// <summary>The developer app's homepage. <see langword="null"/> for seeded and dynamically registered clients.</summary>
    public string? HomepageUrl { get; init; }

    /// <summary>The developer app's description, when it has one. <see langword="null"/> for other clients.</summary>
    public string? Description { get; init; }

    /// <summary>
    /// Whether the developer app is confidential (has a client secret). <see langword="null"/> for seeded and
    /// dynamically registered clients.
    /// </summary>
    public bool? Confidential { get; init; }

    /// <summary>
    /// Who built the developer app, as the host's <see cref="IOAuthDeveloperAppOwnerDisplay"/> describes them.
    /// <see langword="null"/> when no display is registered (the default), when it returns nothing, and for other clients.
    /// </summary>
    public string? Owner { get; init; }
}

public enum OAuthConsentStatus
{
    /// <summary>A code was issued. Send the browser to <see cref="OAuthConsentResult.RedirectUrl"/>.</summary>
    Approved,

    /// <summary>The user denied. Send the browser to <see cref="OAuthConsentResult.RedirectUrl"/>.</summary>
    Denied,

    /// <summary>The request is unknown, expired, already used, or belongs to another user.</summary>
    NotFound,

    /// <summary>The principal factory returned <see langword="null"/>. The request was not consumed.</summary>
    Declined,
}

/// <summary>The outcome of an approve or deny call.</summary>
public sealed record OAuthConsentResult(
    OAuthConsentStatus Status,
    string? RedirectUrl = null,
    string? ClientId = null,
    string? AuthorizationId = null)
{
    internal static readonly OAuthConsentResult NotFound = new(OAuthConsentStatus.NotFound);
    internal static readonly OAuthConsentResult Declined = new(OAuthConsentStatus.Declined);
}

/// <summary>
/// Reads, approves, and denies pending consent requests. Use it from the host's own consent endpoints,
/// or map the defaults with <c>MapOAuthConsentEndpoints</c>. It uses the scoped DbContext, so a host
/// transaction around a call also covers the OpenIddict rows it writes.
/// </summary>
public interface IOAuthConsentService
{
    /// <summary>The usable request with this id that belongs to <paramref name="userId"/>, or <see langword="null"/>.</summary>
    Task<OAuthPendingRequest?> FindAsync(Guid requestId, string userId, CancellationToken cancellationToken = default);

    /// <summary>Approves with the registered <see cref="IOAuthPrincipalFactory"/>.</summary>
    Task<OAuthConsentResult> ApproveAsync(Guid requestId, string userId, CancellationToken cancellationToken = default);

    /// <summary>Approves with a principal built by <paramref name="createPrincipal"/> for this call.</summary>
    Task<OAuthConsentResult> ApproveAsync(
        Guid requestId,
        string userId,
        Func<OAuthPrincipalContext, ValueTask<ClaimsPrincipal?>> createPrincipal,
        CancellationToken cancellationToken = default);

    /// <summary>Consumes the request and returns an <c>access_denied</c> redirect for the client.</summary>
    Task<OAuthConsentResult> DenyAsync(Guid requestId, string userId, CancellationToken cancellationToken = default);

    /// <summary>Revokes an authorization and every token issued from it. Returns <see langword="false"/> when it does not exist.</summary>
    Task<bool> RevokeAuthorizationAsync(string authorizationId, CancellationToken cancellationToken = default);
}

internal sealed class OAuthConsentService<TContext, TKey>(
    TContext db,
    IHttpContextAccessor httpContextAccessor,
    IOAuthPrincipalFactory principalFactory,
    IOAuthUserValidator userValidator,
    IOpenIddictServerDispatcher dispatcher,
    IOptionsMonitor<OpenIddictServerOptions> serverOptions,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens,
    IOptions<OAuthServerOptions> options,
    IOAuthDeveloperAppOwnerDisplay ownerDisplay,
    TimeProvider clock) : IOAuthConsentService
    where TContext : DbContext
    where TKey : IEquatable<TKey>
{
    private DbSet<OAuthRequest<TKey>> Requests => db.Set<OAuthRequest<TKey>>();

    public async Task<OAuthPendingRequest?> FindAsync(Guid requestId, string userId, CancellationToken cancellationToken = default)
    {
        if (!TryKey(userId, out var key))
        {
            return null;
        }

        var loaded = await LoadAsync(requestId, key, cancellationToken);
        return loaded is null ? null : await ToPendingAsync(loaded, userId, cancellationToken);
    }

    public Task<OAuthConsentResult> ApproveAsync(Guid requestId, string userId, CancellationToken cancellationToken = default)
        => ApproveAsync(requestId, userId, context => principalFactory.CreateAsync(context, cancellationToken), cancellationToken);

    public async Task<OAuthConsentResult> ApproveAsync(
        Guid requestId,
        string userId,
        Func<OAuthPrincipalContext, ValueTask<ClaimsPrincipal?>> createPrincipal,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(createPrincipal);
        if (!TryKey(userId, out var key))
        {
            return OAuthConsentResult.NotFound;
        }

        var loaded = await LoadAsync(requestId, key, cancellationToken);
        if (loaded is null)
        {
            return OAuthConsentResult.NotFound;
        }

        var row = loaded.Request;
        var http = httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException("ApproveAsync must run inside an HTTP request.");
        var pending = await ToPendingAsync(loaded, userId, cancellationToken);
        var principal = await createPrincipal(new OAuthPrincipalContext(http, userId, pending));
        if (principal is null)
        {
            return OAuthConsentResult.Declined;
        }

        if (string.IsNullOrEmpty(principal.GetClaim(OpenIddictConstants.Claims.Subject)))
        {
            throw new InvalidOperationException("The OAuth principal must have a 'sub' claim.");
        }

        if (!await ConsumeAsync(requestId, key, cancellationToken))
        {
            return OAuthConsentResult.NotFound;
        }

        await OAuthGrantClaims.AddAsync(principal, userId, userValidator, cancellationToken);
        var issuer = options.Value.Issuer!;
        var issued = await OAuthCodeIssuer.IssueAsync(
            dispatcher,
            serverOptions.CurrentValue,
            issuer,
            row.ClientId,
            row.RedirectUri,
            row.CodeChallenge,
            row.Scope,
            row.Resource,
            principal,
            cancellationToken);
        var redirect = OAuthRedirects.Authorization(row.RedirectUri, issued.Code, row.State, issuer.AbsoluteUri, null, null);
        return new OAuthConsentResult(OAuthConsentStatus.Approved, redirect, row.ClientId, issued.AuthorizationId);
    }

    public async Task<OAuthConsentResult> DenyAsync(Guid requestId, string userId, CancellationToken cancellationToken = default)
    {
        if (!TryKey(userId, out var key))
        {
            return OAuthConsentResult.NotFound;
        }

        var row = (await LoadAsync(requestId, key, cancellationToken))?.Request;
        if (row is null || !await ConsumeAsync(requestId, key, cancellationToken))
        {
            return OAuthConsentResult.NotFound;
        }

        var redirect = OAuthRedirects.Authorization(
            row.RedirectUri,
            null,
            row.State,
            options.Value.Issuer!.AbsoluteUri,
            OpenIddictConstants.Errors.AccessDenied,
            "The request was denied.");
        return new OAuthConsentResult(OAuthConsentStatus.Denied, redirect, row.ClientId);
    }

    public async Task<bool> RevokeAuthorizationAsync(string authorizationId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(authorizationId);
        var authorization = await authorizations.FindByIdAsync(authorizationId, cancellationToken);
        if (authorization is null)
        {
            return false;
        }

        await tokens.RevokeByAuthorizationIdAsync(authorizationId, cancellationToken);
        await authorizations.TryRevokeAsync(authorization, cancellationToken);
        return true;
    }

    /// <summary>
    /// The usable request, with the developer app row for its client when there is one. One statement: the app is
    /// a left join on its unique client id, so seeded and dynamically registered clients cost nothing extra.
    /// The app is read when the card is fetched, not copied at authorize.
    /// </summary>
    private async Task<LoadedRequest?> LoadAsync(Guid requestId, TKey key, CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        var loaded = await (
                from request in Requests.AsNoTracking()
                where request.Id == requestId && request.UserId.Equals(key)
                    && request.ConsumedAt == null && request.ExpiresAt > now
                join app in db.Set<OAuthDeveloperApp<TKey>>().AsNoTracking()
                    on request.ClientId equals app.ClientId into apps
                from app in apps.DefaultIfEmpty()
                select new { Request = request, App = app })
            .FirstOrDefaultAsync(cancellationToken);
        return loaded is null ? null : new LoadedRequest(loaded.Request, loaded.App);
    }

    /// <summary>Marks the request used. Only one caller wins when two race.</summary>
    private async Task<bool> ConsumeAsync(Guid requestId, TKey key, CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        var won = await Requests
            .Where(request => request.Id == requestId && request.UserId.Equals(key)
                && request.ConsumedAt == null && request.ExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(request => request.ConsumedAt, now), cancellationToken);
        return won == 1;
    }

    private async Task<OAuthPendingRequest> ToPendingAsync(LoadedRequest loaded, string userId, CancellationToken cancellationToken)
    {
        var row = loaded.Request;
        var pending = new OAuthPendingRequest(
            row.Id,
            userId,
            row.ClientId,
            row.ClientName,
            row.RedirectUri,
            row.RedirectHost,
            OAuthScopes.Split(row.Scope),
            row.Resource,
            row.CreatedAt,
            row.ExpiresAt);
        if (loaded.App is not { } app)
        {
            return pending;
        }

        var owner = await ownerDisplay.GetOwnerAsync(
            new OAuthDeveloperAppOwnerContext(app.Id, app.ClientId, KeyToString(app.OwnerId)), cancellationToken);
        return pending with
        {
            HomepageUrl = app.HomepageUrl,
            Description = app.Description,
            Confidential = app.Confidential,
            Owner = string.IsNullOrWhiteSpace(owner) ? null : owner.Trim(),
        };
    }

    private sealed record LoadedRequest(OAuthRequest<TKey> Request, OAuthDeveloperApp<TKey>? App);

    internal static bool TryKey(string? value, out TKey key)
    {
        key = default!;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        try
        {
            var converted = TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(value);
            if (converted is TKey typed)
            {
                key = typed;
                return true;
            }
        }
        catch (Exception ex) when (ex is FormatException or NotSupportedException or ArgumentException)
        {
        }

        return false;
    }

    internal static string KeyToString(TKey key)
        => Convert.ToString(key, CultureInfo.InvariantCulture) ?? string.Empty;
}
