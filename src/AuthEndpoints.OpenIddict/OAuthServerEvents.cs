using System.Data.Common;
using System.Globalization;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>What happened, in an <see cref="OAuthServerEvent"/>.</summary>
public enum OAuthServerEventType
{
    /// <summary>The user approved a consent request and an authorization code was issued.</summary>
    ConsentApproved,

    /// <summary>The user denied a consent request.</summary>
    ConsentDenied,

    /// <summary>The client exchanged an authorization code for tokens.</summary>
    CodeExchanged,

    /// <summary>The client used a refresh token and got new tokens.</summary>
    TokenRefreshed,

    /// <summary>
    /// A code exchange or refresh was refused because the approving user may no longer use the grant (user revalidation:
    /// a changed security stamp, lockout, deleted account). The grant and its tokens were revoked.
    /// </summary>
    GrantRefused,

    /// <summary>A grant (OpenIddict authorization) and its tokens were revoked. <see cref="OAuthServerEvent.RevokedBy"/> says by whom.</summary>
    AuthorizationRevoked,

    /// <summary>
    /// A client was added: by dynamic registration, from a client ID metadata document (the first time it is stored), or as
    /// a developer app. <see cref="OAuthServerEvent.ClientKind"/> says which.
    /// </summary>
    ClientRegistered,
}

/// <summary>Who or what revoked a grant, for <see cref="OAuthServerEventType.AuthorizationRevoked"/>.</summary>
public enum OAuthRevokedBy
{
    /// <summary>The user who approved it, for example from a connected apps page.</summary>
    User,

    /// <summary>
    /// Host code acting for someone else, such as an admin. <see cref="OAuthServerEvent.ActorId"/> holds the actor's id when
    /// the host passed one. <see cref="IOAuthConsentService.RevokeAuthorizationAsync"/> reports this.
    /// </summary>
    Admin,

    /// <summary>The background cleanup, for example for a developer app whose owner was deleted.</summary>
    Cleanup,

    /// <summary>The client was deleted, for example a developer app by its owner.</summary>
    ClientDeleted,
}

/// <summary>
/// Kinds of OAuth client, derived from what the application store holds. Strings, so more kinds can be added later
/// without breaking callers. Treat an unknown value like <see cref="Configured"/>.
/// </summary>
public static class OAuthClientKinds
{
    /// <summary>A client from <see cref="OAuthServerOptions.Clients"/>, or one the host created in OpenIddict itself.</summary>
    public const string Configured = "configured";

    /// <summary>A client created by dynamic registration (<c>POST /connect/register</c>).</summary>
    public const string Dynamic = "dynamic";

    /// <summary>A client identified by a client ID metadata document (its <c>client_id</c> is an <c>https</c> URL).</summary>
    public const string MetadataDocument = "metadata_document";

    /// <summary>A developer app that a signed-in user registered and owns.</summary>
    public const string DeveloperApp = "developer_app";

    /// <summary>The kind of a client, from its application settings.</summary>
    internal static string From(IReadOnlyDictionary<string, string> settings)
        => settings.ContainsKey(OAuthServerConstants.DeveloperAppSetting) ? DeveloperApp
            : settings.ContainsKey(OAuthServerConstants.ClientMetadataExpiresSetting) ? MetadataDocument
            : settings.ContainsKey(OAuthServerConstants.CreatedAtSetting) ? Dynamic
            : Configured;
}

/// <summary>
/// Something the OAuth server did, for an audit trail. It names the user, client, and grant involved, and never carries
/// a token, an authorization code, a client secret, or the user's security stamp.
/// </summary>
public sealed record OAuthServerEvent(OAuthServerEventType Type, DateTimeOffset OccurredAt)
{
    /// <summary>
    /// The user who approved the grant (for <see cref="OAuthServerEventType.ClientRegistered"/> of a developer app, its owner).
    /// This is the Identity user id even when a principal factory issued the tokens for another subject.
    /// <see langword="null"/> when no user is involved (dynamic registration) or for a grant stored before this was recorded.
    /// </summary>
    public string? UserId { get; init; }

    /// <summary>The client's <c>client_id</c>.</summary>
    public string? ClientId { get; init; }

    /// <summary>One of <see cref="OAuthClientKinds"/>, when the client is still stored.</summary>
    public string? ClientKind { get; init; }

    /// <summary>The OpenIddict authorization (grant) id, when a grant is involved.</summary>
    public string? AuthorizationId { get; init; }

    /// <summary>The granted or requested scopes.</summary>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>The resource (RFC 8707 audience) of the grant, when known.</summary>
    public string? Resource { get; init; }

    /// <summary><c>authorization_code</c> or <c>refresh_token</c>, for token endpoint events.</summary>
    public string? GrantType { get; init; }

    /// <summary>Who revoked the grant, for <see cref="OAuthServerEventType.AuthorizationRevoked"/>.</summary>
    public OAuthRevokedBy? RevokedBy { get; init; }

    /// <summary>The id of whoever acted for the user, such as an admin, when the host passed one.</summary>
    public string? ActorId { get; init; }
}

/// <summary>
/// Receives <see cref="OAuthServerEvent"/>s, for example to write an audit log. Register any number with
/// <c>AddServerEvents&lt;T&gt;()</c>; with none (the default) nothing is raised. Subscribers are scoped and run in the
/// request, one after another, so keep them fast or hand the event to a queue. One that throws is logged and skipped:
/// the OAuth flow and the other subscribers carry on.
/// <para>
/// With the EF Core stores, when the change behind an event happens while the host has a transaction open on the server's DbContext
/// (<c>db.Database.BeginTransactionAsync()</c>, for example around <see cref="IOAuthConsentService.ApproveAsync(Guid, string, CancellationToken)"/>), the
/// event is held back: subscribers get it after that transaction commits, and never if it rolls back. Commit or roll back
/// through the <c>IDbContextTransaction</c> EF Core returned; a transaction EF Core cannot see (<c>TransactionScope</c>,
/// or a <c>DbTransaction</c> committed directly) does not defer events.
/// </para>
/// </summary>
public interface IOAuthServerEvents
{
    ValueTask OnEventAsync(OAuthServerEvent serverEvent, CancellationToken cancellationToken);
}

/// <summary>Calls every registered <see cref="IOAuthServerEvents"/>, isolating failures.</summary>
internal sealed partial class OAuthServerEventDispatcher(
    IEnumerable<IOAuthServerEvents> subscribers,
    TimeProvider clock,
    IServiceProvider services,
    ILogger<OAuthServerEventDispatcher> logger)
{
    private readonly IOAuthServerEvents[] _subscribers = subscribers.ToArray();

    public bool HasSubscribers => _subscribers.Length > 0;

    public DateTimeOffset Now => clock.GetUtcNow();

    /// <summary>
    /// Raises the event now, or, while the store has a transaction open (<see cref="IOAuthServerEventTransactions"/>), once
    /// that transaction commits (dropped on rollback).
    /// </summary>
    public ValueTask RaiseAsync(OAuthServerEvent serverEvent, CancellationToken cancellationToken)
    {
        if (!HasSubscribers)
        {
            return ValueTask.CompletedTask;
        }

        if (services.GetService<IOAuthServerEventTransactions>() is { } transactions
            && transactions.TryDefer(token => PublishAsync(serverEvent, token)))
        {
            return ValueTask.CompletedTask;
        }

        return PublishAsync(serverEvent, cancellationToken);
    }

    private async ValueTask PublishAsync(OAuthServerEvent serverEvent, CancellationToken cancellationToken)
    {
        foreach (var subscriber in _subscribers)
        {
            try
            {
                await subscriber.OnEventAsync(serverEvent, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                LogSubscriberFailed(ex, serverEvent.Type, subscriber.GetType().FullName ?? subscriber.GetType().Name);
            }
        }
    }

    /// <summary>
    /// Raises <see cref="OAuthServerEventType.AuthorizationRevoked"/> for one grant, read from the store. Call it before the
    /// grant is deleted; a revoked grant is still readable.
    /// </summary>
    public async ValueTask RevokedAsync(
        IOpenIddictAuthorizationManager authorizations,
        IOpenIddictApplicationManager applications,
        object authorization,
        OAuthRevokedBy revokedBy,
        string? actorId,
        CancellationToken cancellationToken)
    {
        if (!HasSubscribers)
        {
            return;
        }

        var grant = await OAuthAuthorizationRecord.ReadAsync(authorizations, applications, authorization, cancellationToken);
        await RevokedAsync(grant, revokedBy, actorId, cancellationToken);
    }

    /// <summary>Raises <see cref="OAuthServerEventType.AuthorizationRevoked"/> for a grant read earlier.</summary>
    public async ValueTask RevokedAsync(OAuthAuthorizationRecord grant, OAuthRevokedBy revokedBy, string? actorId, CancellationToken cancellationToken)
    {
        if (!HasSubscribers)
        {
            return;
        }

        await RaiseAsync(new OAuthServerEvent(OAuthServerEventType.AuthorizationRevoked, Now)
        {
            UserId = grant.UserId,
            ClientId = grant.ClientId,
            ClientKind = grant.ClientKind,
            AuthorizationId = grant.Id,
            Scopes = grant.Scopes,
            Resource = grant.Resource,
            RevokedBy = revokedBy,
            ActorId = actorId,
        }, cancellationToken);
    }

    /// <summary>
    /// The valid grants of one client, read untracked before a bulk revocation so each can be reported. Empty without
    /// subscribers.
    /// </summary>
    public async ValueTask<IReadOnlyList<OAuthAuthorizationRecord>> ValidAuthorizationsAsync(
        string applicationId, CancellationToken cancellationToken)
        => HasSubscribers
            ? await services.GetRequiredService<IOAuthServerQueries>().ListValidGrantsAsync(applicationId, cancellationToken)
            : [];

    [LoggerMessage(Level = LogLevel.Error, Message = "An OAuth server event subscriber failed. Event: {EventType}. Subscriber: {Subscriber}")]
    private partial void LogSubscriberFailed(Exception ex, OAuthServerEventType eventType, string subscriber);
}

/// <summary>
/// A grant (an OpenIddict authorization) as AuthEndpoints reports it: the approving user, the client, and the properties
/// this package adds. Returned by <see cref="IOAuthServerQueries"/>.
/// </summary>
/// <param name="Id">The OpenIddict authorization id.</param>
/// <param name="UserId">The approving user: the <see cref="OAuthServerConstants.AuthorizationUserProperty"/> property, or the subject.</param>
/// <param name="ClientId">The client id, or <see langword="null"/> when the client is no longer stored.</param>
/// <param name="ClientKind">One of <see cref="OAuthClientKinds"/>, or <see langword="null"/> without a stored client.</param>
/// <param name="Scopes">The granted scopes.</param>
/// <param name="Resource">The <see cref="OAuthServerConstants.AuthorizationResourceProperty"/> property.</param>
/// <param name="LastUsedAt">The <see cref="OAuthServerConstants.AuthorizationLastUsedProperty"/> property.</param>
public sealed record OAuthAuthorizationRecord(
    string? Id,
    string? UserId,
    string? ClientId,
    string? ClientKind,
    IReadOnlyList<string> Scopes,
    string? Resource,
    DateTimeOffset? LastUsedAt)
{
    /// <summary>When the grant was created, when the store has it.</summary>
    public DateTimeOffset? CreatedAt { get; init; }

    /// <summary>The client's display name, when the client is still stored.</summary>
    public string? ClientName { get; init; }

    /// <summary>
    /// Reads one grant through OpenIddict's managers, whatever stores them. Use it to build the records of a custom
    /// <see cref="IOAuthServerQueries"/>.
    /// </summary>
    public static async ValueTask<OAuthAuthorizationRecord> ReadAsync(
        IOpenIddictAuthorizationManager authorizations,
        IOpenIddictApplicationManager applications,
        object authorization,
        CancellationToken cancellationToken)
    {
        var properties = await authorizations.GetPropertiesAsync(authorization, cancellationToken);
        var userId = OAuthAuthorizationProperties.String(properties, OAuthServerConstants.AuthorizationUserProperty)
            ?? await authorizations.GetSubjectAsync(authorization, cancellationToken);
        ArgumentNullException.ThrowIfNull(authorizations);
        ArgumentNullException.ThrowIfNull(applications);
        ArgumentNullException.ThrowIfNull(authorization);
        string? clientId = null;
        string? kind = null;
        string? clientName = null;
        if (await authorizations.GetApplicationIdAsync(authorization, cancellationToken) is { Length: > 0 } applicationId
            && await applications.FindByIdAsync(applicationId, cancellationToken) is { } application)
        {
            clientId = await applications.GetClientIdAsync(application, cancellationToken);
            kind = OAuthClientKinds.From(await applications.GetSettingsAsync(application, cancellationToken));
            clientName = await applications.GetDisplayNameAsync(application, cancellationToken);
        }

        var created = await authorizations.GetCreationDateAsync(authorization, cancellationToken);
        return new OAuthAuthorizationRecord(
            await authorizations.GetIdAsync(authorization, cancellationToken),
            userId,
            clientId,
            kind,
            (await authorizations.GetScopesAsync(authorization, cancellationToken)).ToArray(),
            OAuthAuthorizationProperties.String(properties, OAuthServerConstants.AuthorizationResourceProperty),
            OAuthAuthorizationProperties.Time(properties, OAuthServerConstants.AuthorizationLastUsedProperty))
        {
            CreatedAt = created,
            ClientName = clientName,
        };
    }
}

/// <summary>The properties this package stores on an OpenIddict authorization.</summary>
internal static class OAuthAuthorizationProperties
{
    /// <summary>
    /// Records the approving user and the approved resource on a new grant. The user id lets userinfo, logout, events and
    /// the connected apps list find the user even when a principal factory chose another <c>sub</c>.
    /// </summary>
    public static async Task SetApprovalAsync(
        IOpenIddictAuthorizationManager authorizations,
        string authorizationId,
        string userId,
        string? resource,
        CancellationToken cancellationToken)
    {
        var authorization = await authorizations.FindByIdAsync(authorizationId, cancellationToken)
            ?? throw new InvalidOperationException("The authorization was not stored.");
        var descriptor = new OpenIddictAuthorizationDescriptor();
        await authorizations.PopulateAsync(descriptor, authorization, cancellationToken);
        descriptor.Properties[OAuthServerConstants.AuthorizationUserProperty] = JsonSerializer.SerializeToElement(userId);
        if (!string.IsNullOrEmpty(resource))
        {
            descriptor.Properties[OAuthServerConstants.AuthorizationResourceProperty] = JsonSerializer.SerializeToElement(resource);
        }

        await authorizations.UpdateAsync(authorization, descriptor, cancellationToken);
    }

    public static string? String(IReadOnlyDictionary<string, JsonElement> properties, string name)
        => properties.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    public static DateTimeOffset? Time(IReadOnlyDictionary<string, JsonElement> properties, string name)
        => String(properties, name) is { } raw
            && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var value)
                ? value
                : null;
}

/// <summary>
/// Runs at the token endpoint after OpenIddict generated and stored the new tokens for a code or refresh grant. Records
/// "last used" on the grant when <see cref="OAuthServerOptions.RecordLastUsed"/> is on, and raises
/// <see cref="OAuthServerEventType.CodeExchanged"/> or <see cref="OAuthServerEventType.TokenRefreshed"/>.
/// </summary>
internal sealed partial class RaiseTokenEvents(
    OAuthServerEventDispatcher events,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictApplicationManager applications,
    IOptions<OAuthServerOptions> options,
    IServiceProvider services,
    ILogger<RaiseTokenEvents> logger) : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        var settings = options.Value;
        if (context.IsRejected
            || context.EndpointType != OpenIddictServerEndpointType.Token
            || context.Transaction.GetHttpRequest() is null
            || context.Request is not { } request
            || context.Principal is not { } principal
            || !(request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
            || (!events.HasSubscribers && !settings.RecordLastUsed))
        {
            return;
        }

        var authorizationId = principal.GetAuthorizationId();
        if (settings.RecordLastUsed && !string.IsNullOrEmpty(authorizationId))
        {
            await RecordLastUsedAsync(authorizationId, settings.LastUsedInterval, events.Now, context.CancellationToken);
        }

        if (!events.HasSubscribers)
        {
            return;
        }

        string? kind = null;
        if (request.ClientId is { Length: > 0 } clientId
            && await applications.FindByClientIdAsync(clientId, context.CancellationToken) is { } application)
        {
            kind = OAuthClientKinds.From(await applications.GetSettingsAsync(application, context.CancellationToken));
        }

        await events.RaiseAsync(new OAuthServerEvent(
            request.IsAuthorizationCodeGrantType() ? OAuthServerEventType.CodeExchanged : OAuthServerEventType.TokenRefreshed,
            events.Now)
        {
            UserId = principal.GetClaim(OAuthServerConstants.UserIdClaim),
            ClientId = request.ClientId,
            ClientKind = kind,
            AuthorizationId = authorizationId,
            Scopes = principal.GetScopes().ToArray(),
            Resource = principal.GetResources().FirstOrDefault(),
            GrantType = request.GrantType,
        }, context.CancellationToken);
    }

    private async Task RecordLastUsedAsync(string authorizationId, TimeSpan interval, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (await authorizations.FindByIdAsync(authorizationId, cancellationToken) is not { } authorization)
        {
            return;
        }

        var properties = await authorizations.GetPropertiesAsync(authorization, cancellationToken);
        if (OAuthAuthorizationProperties.Time(properties, OAuthServerConstants.AuthorizationLastUsedProperty) is { } last
            && now - last < interval)
        {
            return;
        }

        var descriptor = new OpenIddictAuthorizationDescriptor();
        await authorizations.PopulateAsync(descriptor, authorization, cancellationToken);
        descriptor.Properties[OAuthServerConstants.AuthorizationLastUsedProperty]
            = JsonSerializer.SerializeToElement(now.ToString("O", CultureInfo.InvariantCulture));
        try
        {
            await authorizations.UpdateAsync(authorization, descriptor, cancellationToken);
        }
        catch (OpenIddictExceptions.ConcurrencyException ex)
        {
            // Another request updated or deleted the grant first. The time is a hint; the next refresh records it.
            LogLastUsedSkipped(ex);
            await ResetAsync(authorization, cancellationToken);
        }
    }

    /// <summary>
    /// A store may still hold the values this write set, with a concurrency token it never stored (EF Core's change tracker
    /// does). Refresh the grant so a later update of it in this request (another handler, or host code) starts from the
    /// stored values instead of failing again.
    /// </summary>
    private async Task ResetAsync(object authorization, CancellationToken cancellationToken)
    {
        if (services.GetService<IOAuthAuthorizationRefresher>() is { } refresher)
        {
            await refresher.RefreshAsync(authorization, cancellationToken);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "The OAuth grant's last-used time was not recorded")]
    private partial void LogLastUsedSkipped(Exception ex);
}
