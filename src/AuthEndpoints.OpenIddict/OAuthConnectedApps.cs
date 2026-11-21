using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using AuthEndpoints.Identity;

namespace AuthEndpoints.OpenIddict;

/// <summary>A live OAuth grant of one user: a client the user connected and has not disconnected.</summary>
/// <param name="AuthorizationId">The OpenIddict authorization id. Pass it to <see cref="IOAuthConnectedAppService.RevokeAsync(string, string, CancellationToken)"/>.</param>
/// <param name="ClientId">The client's <c>client_id</c>.</param>
/// <param name="ClientName">The client's display name.</param>
/// <param name="ClientKind">One of <see cref="OAuthClientKinds"/>, derived from what the application store holds.</param>
/// <param name="Scopes">The granted scopes.</param>
public sealed record OAuthConnectedApp(
    [property: JsonPropertyName("authorizationId")] string AuthorizationId,
    [property: JsonPropertyName("clientId")] string ClientId,
    [property: JsonPropertyName("clientName")] string ClientName,
    [property: JsonPropertyName("clientKind")] string ClientKind,
    [property: JsonPropertyName("scopes")] IReadOnlyList<string> Scopes)
{
    /// <summary>
    /// The client's domain, when it is known: the host of a client ID metadata document URL, or of a developer app's
    /// homepage. <see langword="null"/> for configured and dynamically registered clients, whose names are not tied to a domain.
    /// </summary>
    [JsonPropertyName("clientHost")]
    public string? ClientHost { get; init; }

    /// <summary><see cref="Scopes"/> with the display names and descriptions of <see cref="OAuthServerOptions.ScopeDefinitions"/>, for the request culture.</summary>
    [JsonPropertyName("scopeDetails")]
    public IReadOnlyList<OAuthScopeDetail> ScopeDetails { get; init; } = [];

    /// <summary>The resource (audience) the user approved. <see langword="null"/> for grants stored before it was recorded.</summary>
    [JsonPropertyName("resource")]
    public string? Resource { get; init; }

    /// <summary>When the user approved the client.</summary>
    [JsonPropertyName("createdAt")]
    public DateTimeOffset? CreatedAt { get; init; }

    /// <summary>
    /// When the client last used the grant at the token endpoint. <see langword="null"/> unless
    /// <see cref="OAuthServerOptions.RecordLastUsed"/> is on.
    /// </summary>
    [JsonPropertyName("lastUsedAt")]
    public DateTimeOffset? LastUsedAt { get; init; }
}

/// <summary>
/// The clients a user connected (their live OAuth grants), and a revoke that checks ownership. The routes mapped by
/// <c>MapOAuthServer</c> call it for the signed-in user. Admin code calls it with any user id: the package does not decide
/// who is an admin, so check that before you call it.
/// </summary>
public interface IOAuthConnectedAppService
{
    /// <summary>
    /// The user's live grants, newest first. A grant is live when it is not revoked and still has a valid token. Grants
    /// issued for another <c>sub</c> by a principal factory are included: ownership is the approving user.
    /// </summary>
    Task<IReadOnlyList<OAuthConnectedApp>> ListAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the grant and every token issued from it, when it belongs to <paramref name="userId"/> and is not revoked yet,
    /// and raises <see cref="OAuthServerEventType.AuthorizationRevoked"/> with <see cref="OAuthRevokedBy.User"/>.
    /// Returns <see langword="false"/> otherwise, without telling an unknown grant from someone else's.
    /// </summary>
    Task<bool> RevokeAsync(string userId, string authorizationId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Like <see cref="RevokeAsync(string, string, CancellationToken)"/>, reporting who acted: for example
    /// <see cref="OAuthRevokedBy.Admin"/> and the admin's user id from an admin page.
    /// </summary>
    Task<bool> RevokeAsync(
        string userId, string authorizationId, OAuthRevokedBy revokedBy, string? actorId, CancellationToken cancellationToken = default);
}

internal sealed class OAuthConnectedAppService<TContext, TKey>(
    TContext db,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens,
    OAuthServerEventDispatcher events,
    IOAuthScopeDescriptions scopeDescriptions,
    TimeProvider clock) : IOAuthConnectedAppService
    where TContext : DbContext
    where TKey : IEquatable<TKey>
{
    private static readonly JsonSerializerOptions Relaxed = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public async Task<IReadOnlyList<OAuthConnectedApp>> ListAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(userId);
        var grants = await OwnedAsync(userId, null, cancellationToken);
        if (grants.Count == 0)
        {
            return [];
        }

        // Developer app homepages, in one query.
        var developerClientIds = grants
            .Where(grant => grant.ClientKind == OAuthClientKinds.DeveloperApp)
            .Select(grant => grant.ClientId!)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var homepages = developerClientIds.Count == 0
            ? []
            : await db.Set<OAuthDeveloperApp<TKey>>().AsNoTracking()
                .Where(app => developerClientIds.Contains(app.ClientId))
                .ToDictionaryAsync(app => app.ClientId, app => app.HomepageUrl, StringComparer.Ordinal, cancellationToken);

        // Through IOAuthScopeDescriptions, so the list shows the same text as the consent card, including descriptions
        // an app loads from its own store.
        var details = new Dictionary<string, IReadOnlyList<OAuthScopeDetail>>(StringComparer.Ordinal);
        foreach (var grant in grants)
        {
            var key = string.Join(' ', grant.Scopes);
            if (!details.ContainsKey(key))
            {
                details[key] = await scopeDescriptions.DescribeAsync(grant.Scopes, CultureInfo.CurrentUICulture, cancellationToken);
            }
        }

        return grants
            .OrderByDescending(grant => grant.CreatedAt)
            .Select(grant => new OAuthConnectedApp(
                grant.Id!,
                grant.ClientId!,
                string.IsNullOrWhiteSpace(grant.ClientName) ? OAuthServerConstants.FallbackClientName : grant.ClientName,
                grant.ClientKind ?? OAuthClientKinds.Configured,
                grant.Scopes)
            {
                ClientHost = grant.ClientKind switch
                {
                    OAuthClientKinds.MetadataDocument => OAuthClientMetadataUrl.Host(grant.ClientId!),
                    OAuthClientKinds.DeveloperApp when homepages.TryGetValue(grant.ClientId!, out var homepage)
                        && Uri.TryCreate(homepage, UriKind.Absolute, out var url) => url.Authority,
                    _ => null,
                },
                ScopeDetails = details[string.Join(' ', grant.Scopes)],
                Resource = grant.Resource,
                CreatedAt = grant.CreatedAt,
                LastUsedAt = grant.LastUsedAt,
            })
            .ToList();
    }

    public Task<bool> RevokeAsync(string userId, string authorizationId, CancellationToken cancellationToken = default)
        => RevokeAsync(userId, authorizationId, OAuthRevokedBy.User, null, cancellationToken);

    public async Task<bool> RevokeAsync(
        string userId, string authorizationId, OAuthRevokedBy revokedBy, string? actorId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(userId);
        if (string.IsNullOrEmpty(authorizationId))
        {
            return false;
        }

        // Owned and not revoked. Expired-but-valid grants can be revoked too, so nothing is left to revive.
        var grant = (await OwnedAsync(userId, authorizationId, cancellationToken)).FirstOrDefault();
        if (grant is null || await authorizations.FindByIdAsync(authorizationId, cancellationToken) is not { } authorization)
        {
            return false;
        }

        await tokens.RevokeByAuthorizationIdAsync(authorizationId, cancellationToken);
        if (!await authorizations.TryRevokeAsync(authorization, cancellationToken))
        {
            // Another request revoked it first, and reported it.
            return true;
        }

        await events.RevokedAsync(grant, revokedBy, actorId, cancellationToken);
        return true;
    }

    /// <summary>
    /// The user's grants. Without <paramref name="authorizationId"/>, only live ones (valid, and permanent or with a valid
    /// unexpired token). With it, that grant when it is valid and owned. The database narrows by subject or by the stored user
    /// id's text; ownership is then checked exactly.
    /// </summary>
    private async Task<IReadOnlyList<OAuthAuthorizationRecord>> OwnedAsync(
        string userId, string? authorizationId, CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var relaxed = JsonSerializer.Serialize(userId, Relaxed);
        var strict = JsonSerializer.Serialize(userId);
        const string valid = OpenIddictConstants.Statuses.Valid;
        const string permanent = OpenIddictConstants.AuthorizationTypes.Permanent;
        var rows = authorizationId is null
            ? await OAuthAuthorizationRecord.QueryAsync(
                db,
                authorization => authorization.Status == valid
                    && authorization.Application != null
                    && (authorization.Subject == userId
                        || (authorization.Properties != null
                            && (authorization.Properties.Contains(relaxed) || authorization.Properties.Contains(strict))))
                    && (authorization.Type == permanent
                        || authorization.Tokens.Any(token => token.Status == valid && token.ExpirationDate > now)),
                cancellationToken)
            : await OAuthAuthorizationRecord.QueryAsync(
                db,
                authorization => authorization.Id == authorizationId && authorization.Status == valid,
                cancellationToken);

        // The stored approving user wins over the subject, which a principal factory may have set to someone else.
        return rows.Where(row => string.Equals(row.UserId, userId, StringComparison.Ordinal) && row.ClientId is not null).ToList();
    }
}

internal static class OAuthConnectedAppEndpoints
{
    public static RouteGroupBuilder Map(IEndpointRouteBuilder endpoints, string prefix)
    {
        var settings = endpoints.ServiceProvider.GetRequiredService<IOptions<OAuthServerOptions>>().Value;
        var group = endpoints.MapGroup(prefix)
            .WithTags("OAuth connected apps")
            // The sign-in scheme (the Identity cookie by default), never the OAuth validation scheme: an access token must
            // not be able to list or end the grants it came from.
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = settings.AuthenticationScheme })
            .RefuseDelegatedCallers("OAuth access tokens cannot manage connected apps.");

        group.MapGet("/", ListAsync)
            .WithName("ListOAuthConnectedApps")
            .WithSummary("The clients the signed-in user connected (live OAuth grants)")
            .Produces<OAuthConnectedApp[]>()
            .ProducesProblem(StatusCodes.Status403Forbidden);
        group.MapDelete("/{id}", RevokeAsync)
            .WithName("RevokeOAuthConnectedApp")
            .WithSummary("Disconnect a client: revoke the grant and its tokens")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .RequireAntiforgery(allowBearer: false);
        return group;
    }

    private static async Task<IResult> ListAsync(
        HttpContext http, IOAuthConnectedAppService apps, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        return UserId(http, options.Value) is { } userId
            ? Results.Ok(await apps.ListAsync(userId, ct))
            : Results.Ok(Array.Empty<OAuthConnectedApp>());
    }

    private static async Task<IResult> RevokeAsync(
        string id, HttpContext http, IOAuthConnectedAppService apps, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        return UserId(http, options.Value) is { } userId && await apps.RevokeAsync(userId, id, ct)
            ? Results.NoContent()
            : Results.Problem(
                statusCode: StatusCodes.Status404NotFound,
                title: "Not found",
                detail: "This connected app is unknown or already disconnected.");
    }

    private static string? UserId(HttpContext http, OAuthServerOptions options)
        => http.User.FindFirst(options.UserIdClaimType)?.Value;
}
