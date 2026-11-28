namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Reads and writes pending consent requests (<see cref="OAuthRequest{TKey}"/>). The authorize endpoint creates one per
/// request that needs the user's approval; the consent service loads it and consumes it once.
/// </summary>
/// <remarks>Each method is one atomic operation. Times are UTC.</remarks>
public interface IOAuthRequestStore<TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>Inserts <paramref name="request"/>.</summary>
    Task CreateAsync(OAuthRequest<TKey> request, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the request when it belongs to <paramref name="userId"/>, is not consumed, and expires after
    /// <paramref name="now"/>; otherwise <see langword="null"/>.
    /// </summary>
    Task<OAuthRequest<TKey>?> FindLiveAsync(Guid id, TKey userId, DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>
    /// Sets <see cref="OAuthRequest{TKey}.ConsumedAt"/> to <paramref name="now"/> when the request belongs to
    /// <paramref name="userId"/>, is not consumed, and expires after <paramref name="now"/>, and returns whether it did.
    /// Of two concurrent calls for one request, at most one returns <see langword="true"/>: that decides which answer
    /// (approve or deny) wins.
    /// </summary>
    Task<bool> TryConsumeAsync(Guid id, TKey userId, DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>Deletes the requests that expire at or before <paramref name="now"/>, and returns how many.</summary>
    Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>
/// Reads and writes developer apps (<see cref="OAuthDeveloperApp{TKey}"/>). The OpenIddict application of an app is
/// stored by OpenIddict; this store keeps the row that says who owns it and whether it may be used.
/// </summary>
/// <remarks>Each method is one atomic operation. Lists are ordered by <see cref="OAuthDeveloperApp{TKey}.CreatedAt"/>.</remarks>
public interface IOAuthDeveloperAppStore<TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>Returns the apps of one owner.</summary>
    Task<IReadOnlyList<OAuthDeveloperApp<TKey>>> ListByOwnerAsync(TKey ownerId, CancellationToken cancellationToken);

    /// <summary>Returns the apps with one status, for admin review.</summary>
    Task<IReadOnlyList<OAuthDeveloperApp<TKey>>> ListByStatusAsync(OAuthDeveloperAppStatus status, CancellationToken cancellationToken);

    /// <summary>Returns the app, or <see langword="null"/>.</summary>
    Task<OAuthDeveloperApp<TKey>?> FindAsync(Guid id, CancellationToken cancellationToken);

    /// <summary>Returns the apps among <paramref name="ids"/> that exist.</summary>
    Task<IReadOnlyList<OAuthDeveloperApp<TKey>>> FindByIdsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken);

    /// <summary>Returns the apps whose <see cref="OAuthDeveloperApp{TKey}.ClientId"/> is among <paramref name="clientIds"/>.</summary>
    Task<IReadOnlyList<OAuthDeveloperApp<TKey>>> FindByClientIdsAsync(
        IReadOnlyCollection<string> clientIds,
        CancellationToken cancellationToken);

    /// <summary>Counts the apps of one owner, for <see cref="OAuthServerOptions.DeveloperApps"/> limits.</summary>
    Task<int> CountByOwnerAsync(TKey ownerId, CancellationToken cancellationToken);

    /// <summary>Inserts <paramref name="app"/>.</summary>
    Task CreateAsync(OAuthDeveloperApp<TKey> app, CancellationToken cancellationToken);

    /// <summary>Stores every value of <paramref name="app"/> on the row with its <see cref="OAuthDeveloperApp{TKey}.Id"/>.</summary>
    Task UpdateAsync(OAuthDeveloperApp<TKey> app, CancellationToken cancellationToken);

    /// <summary>Deletes the app, and returns whether it existed.</summary>
    Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken);

    /// <summary>
    /// Whether the app <paramref name="id"/> exists, has <paramref name="clientId"/>, and is
    /// <see cref="OAuthDeveloperAppStatus.Active"/>. Checked before every authorize and token request of a developer app.
    /// </summary>
    Task<bool> IsActiveAsync(Guid id, string clientId, CancellationToken cancellationToken);
}

/// <summary>
/// Reads OpenIddict's stores in bulk for the lists this package shows and the grants it reports. OpenIddict's managers
/// read one record at a time; these queries read a list in one go. The EF Core implementation joins OpenIddict's tables.
/// </summary>
/// <remarks>
/// A custom implementation can find matching authorizations in its own store and convert each with
/// <see cref="OAuthAuthorizationRecord.ReadAsync"/>. The approving user of a grant is its
/// <see cref="OAuthServerConstants.AuthorizationUserProperty"/> property, or its subject when the property is missing; a
/// principal factory may set a subject that is not the user id.
/// </remarks>
public interface IOAuthServerQueries
{
    /// <summary>
    /// The live grants that <paramref name="userId"/> approved: valid, with a stored client, and either permanent or with a
    /// valid token that expires after <paramref name="now"/>. Each record's <see cref="OAuthAuthorizationRecord.UserId"/> is
    /// the approving user; AuthEndpoints drops a record whose user is not <paramref name="userId"/>.
    /// </summary>
    Task<IReadOnlyList<OAuthAuthorizationRecord>> ListLiveGrantsAsync(
        string userId,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>The grant when it exists and is valid; otherwise <see langword="null"/>.</summary>
    Task<OAuthAuthorizationRecord?> FindValidGrantAsync(string authorizationId, CancellationToken cancellationToken);

    /// <summary>The valid grants of one client, by OpenIddict application id. Read before a bulk revoke, to report each.</summary>
    Task<IReadOnlyList<OAuthAuthorizationRecord>> ListValidGrantsAsync(string applicationId, CancellationToken cancellationToken);

    /// <summary>The redirect URIs of each stored client among <paramref name="clientIds"/>, by client id.</summary>
    Task<IReadOnlyDictionary<string, OAuthClientRedirectUris>> FindRedirectUrisAsync(
        IReadOnlyCollection<string> clientIds,
        CancellationToken cancellationToken);
}

/// <summary>A client's registered redirect URIs.</summary>
/// <param name="RedirectUris">Where an authorization response may go.</param>
/// <param name="PostLogoutRedirectUris">Where an OpenID Connect logout may go.</param>
public sealed record OAuthClientRedirectUris(IReadOnlyList<string> RedirectUris, IReadOnlyList<string> PostLogoutRedirectUris);

/// <summary>
/// Holds <see cref="IOAuthServerEvents"/> events raised while the host has a transaction open on the server's store, and
/// publishes them once it commits. Optional: without one, events are published at once. The EF Core implementation
/// watches the transaction of the server's <c>DbContext</c>.
/// </summary>
public interface IOAuthServerEventTransactions
{
    /// <summary>
    /// Returns <see langword="true"/> when a transaction is open and <paramref name="publish"/> was queued: it runs after
    /// the commit, and never on rollback. Returns <see langword="false"/> to have the event published now.
    /// </summary>
    bool TryDefer(Func<CancellationToken, ValueTask> publish);
}

/// <summary>
/// Restores a grant entity after OpenIddict reported a concurrency failure on it, so a later update of the same grant in
/// the request starts from the stored values. Optional: a store that keeps no per-request state needs none. The EF Core
/// implementation reloads the tracked entity.
/// </summary>
public interface IOAuthAuthorizationRefresher
{
    /// <summary>Reloads <paramref name="authorization"/> from the store, or forgets it when it was deleted.</summary>
    ValueTask RefreshAsync(object authorization, CancellationToken cancellationToken);
}
