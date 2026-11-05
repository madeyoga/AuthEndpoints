using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace AuthEndpoints.OpenIddict;

/// <summary>The editable fields of a developer app.</summary>
public sealed record OAuthDeveloperAppInput(
    string? Name,
    string? HomepageUrl,
    string? Description,
    IReadOnlyList<string>? RedirectUris);

/// <summary>A developer app as its owner or an admin sees it. Never holds the client secret.</summary>
public sealed record OAuthDeveloperAppInfo(
    [property: JsonPropertyName("id")] Guid Id,
    [property: JsonPropertyName("clientId")] string ClientId,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("homepageUrl")] string HomepageUrl,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("redirectUris")] IReadOnlyList<string> RedirectUris,
    [property: JsonPropertyName("confidential")] bool Confidential,
    [property: JsonPropertyName("status")] OAuthDeveloperAppStatus Status,
    [property: JsonPropertyName("createdAt")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("updatedAt")] DateTimeOffset UpdatedAt,
    [property: JsonPropertyName("secretCreatedAt")] DateTimeOffset? SecretCreatedAt)
{
    /// <summary>The owning user's id. Not sent to the owner by the JSON API.</summary>
    [JsonIgnore]
    public string OwnerId { get; init; } = string.Empty;
}

public enum OAuthDeveloperAppOutcome
{
    Succeeded,

    /// <summary>No app with this id belongs to the caller.</summary>
    NotFound,

    /// <summary>The input failed validation. See <see cref="OAuthDeveloperAppResult.Errors"/>.</summary>
    Invalid,

    /// <summary>The owner already has <see cref="OAuthDeveloperAppOptions.MaxAppsPerUser"/> apps.</summary>
    LimitReached,

    /// <summary>A secret was requested for a public app.</summary>
    NotConfidential,
}

/// <summary>
/// The outcome of a developer app change. <see cref="ClientSecret"/> is set only by create (confidential apps)
/// and secret rotation. Show it to the owner once. Only its hash is stored.
/// </summary>
public sealed record OAuthDeveloperAppResult(
    OAuthDeveloperAppOutcome Outcome,
    OAuthDeveloperAppInfo? App = null,
    string? ClientSecret = null,
    IReadOnlyDictionary<string, string[]>? Errors = null);

/// <summary>
/// Developer apps: OAuth clients that signed-in users register and own, like the GitHub or Google developer consoles.
/// The owner methods take the caller's user id and only see that user's apps. <see cref="ListByStatusAsync"/> and
/// <see cref="SetStatusAsync"/> are for admin tools and do not check an owner. Protect them yourself.
/// </summary>
public interface IOAuthDeveloperAppService
{
    Task<IReadOnlyList<OAuthDeveloperAppInfo>> ListAsync(string ownerId, CancellationToken cancellationToken = default);

    Task<OAuthDeveloperAppInfo?> FindAsync(Guid id, string ownerId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers an app. A confidential app gets a generated client secret, authenticates at the token endpoint with it,
    /// and still uses PKCE. A public app (SPA, native, CLI) uses PKCE only. <paramref name="confidential"/> cannot change later.
    /// </summary>
    Task<OAuthDeveloperAppResult> CreateAsync(
        string ownerId, OAuthDeveloperAppInput input, bool confidential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Edits the app. With <see cref="OAuthDeveloperAppOptions.RequireApproval"/>, changing the name or redirect URIs
    /// of an active app sends it back to <see cref="OAuthDeveloperAppStatus.PendingApproval"/> until an admin approves it again.
    /// </summary>
    Task<OAuthDeveloperAppResult> UpdateAsync(
        Guid id, string ownerId, OAuthDeveloperAppInput input, CancellationToken cancellationToken = default);

    /// <summary>Deletes the app with every authorization and token issued to it.</summary>
    Task<bool> DeleteAsync(Guid id, string ownerId, CancellationToken cancellationToken = default);

    /// <summary>Replaces the client secret of a confidential app. The old secret stops working at once.</summary>
    Task<OAuthDeveloperAppResult> RotateSecretAsync(Guid id, string ownerId, CancellationToken cancellationToken = default);

    /// <summary>Admin: every app with this status, for example the review queue.</summary>
    Task<IReadOnlyList<OAuthDeveloperAppInfo>> ListByStatusAsync(
        OAuthDeveloperAppStatus status, CancellationToken cancellationToken = default);

    /// <summary>
    /// Admin: approves, disables, or re-enables an app. Any status other than <see cref="OAuthDeveloperAppStatus.Active"/>
    /// revokes the app's authorizations and tokens. Returns <see langword="false"/> when the app does not exist.
    /// </summary>
    Task<bool> SetStatusAsync(Guid id, OAuthDeveloperAppStatus status, CancellationToken cancellationToken = default);
}

internal static class OAuthDeveloperAppLimits
{
    public const int NameLength = 200;
    public const int DescriptionLength = 1000;
}

/// <summary>Checks whether an OpenIddict application may still be used. Only developer apps can be refused.</summary>
internal interface IOAuthDeveloperAppGate
{
    ValueTask<bool> AllowsAsync(object application, CancellationToken cancellationToken);
}

internal sealed class OAuthDeveloperAppService<TContext, TKey>(
    TContext db,
    IOpenIddictApplicationManager applications,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens,
    IOptions<OAuthServerOptions> options,
    TimeProvider clock) : IOAuthDeveloperAppService, IOAuthDeveloperAppGate
    where TContext : DbContext
    where TKey : IEquatable<TKey>
{
    private DbSet<OAuthDeveloperApp<TKey>> Apps => db.Set<OAuthDeveloperApp<TKey>>();

    public async Task<IReadOnlyList<OAuthDeveloperAppInfo>> ListAsync(string ownerId, CancellationToken cancellationToken = default)
    {
        if (!OAuthConsentService<TContext, TKey>.TryKey(ownerId, out var key))
        {
            return [];
        }

        var rows = await Apps.AsNoTracking()
            .Where(app => app.OwnerId.Equals(key))
            .OrderBy(app => app.CreatedAt)
            .ToListAsync(cancellationToken);
        return await ToInfoAsync(rows, cancellationToken);
    }

    public async Task<OAuthDeveloperAppInfo?> FindAsync(Guid id, string ownerId, CancellationToken cancellationToken = default)
    {
        var row = await LoadAsync(id, ownerId, tracking: false, cancellationToken);
        return row is null ? null : (await ToInfoAsync([row], cancellationToken))[0];
    }

    public async Task<OAuthDeveloperAppResult> CreateAsync(
        string ownerId, OAuthDeveloperAppInput input, bool confidential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!OAuthConsentService<TContext, TKey>.TryKey(ownerId, out var key))
        {
            return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.NotFound);
        }

        var settings = options.Value;
        if (Validate(input, confidential, settings.DeveloperApps) is { } errors)
        {
            return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.Invalid, Errors: errors);
        }

        var owned = await Apps.CountAsync(app => app.OwnerId.Equals(key), cancellationToken);
        if (owned >= settings.DeveloperApps.MaxAppsPerUser)
        {
            return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.LimitReached);
        }

        var now = clock.GetUtcNow();
        var row = new OAuthDeveloperApp<TKey>
        {
            OwnerId = key,
            ClientId = Guid.CreateVersion7().ToString("N"),
            Name = input.Name!.Trim(),
            HomepageUrl = input.HomepageUrl!.Trim(),
            Description = Description(input.Description),
            Confidential = confidential,
            Status = settings.DeveloperApps.RequireApproval ? OAuthDeveloperAppStatus.PendingApproval : OAuthDeveloperAppStatus.Active,
            CreatedAt = now,
            UpdatedAt = now,
            SecretCreatedAt = confidential ? now : null,
        };
        var secret = confidential ? NewSecret() : null;
        var redirects = Redirects(input);
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = row.ClientId,
            ClientSecret = secret,
            ClientType = confidential ? OpenIddictConstants.ClientTypes.Confidential : OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            DisplayName = row.Name,
        };
        foreach (var redirect in redirects)
        {
            descriptor.RedirectUris.Add(new Uri(redirect));
        }

        OAuthClientPermissions.AddCodeFlow(descriptor, settings.Scopes, settings.AllResources());
        descriptor.Settings[OAuthServerConstants.DeveloperAppSetting] = row.Id.ToString();

        // The row goes first. An application without a row is refused and swept, so a failure here never
        // leaves a usable client behind.
        Apps.Add(row);
        await db.SaveChangesAsync(cancellationToken);
        try
        {
            await applications.CreateAsync(descriptor, cancellationToken);
        }
        catch
        {
            await Apps.Where(app => app.Id == row.Id).ExecuteDeleteAsync(CancellationToken.None);
            throw;
        }

        return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.Succeeded, ToInfo(row, redirects), secret);
    }

    public async Task<OAuthDeveloperAppResult> UpdateAsync(
        Guid id, string ownerId, OAuthDeveloperAppInput input, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        var row = await LoadAsync(id, ownerId, tracking: true, cancellationToken);
        if (row is null || await applications.FindByClientIdAsync(row.ClientId, cancellationToken) is not { } application)
        {
            return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.NotFound);
        }

        if (Validate(input, row.Confidential, options.Value.DeveloperApps) is { } errors)
        {
            return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.Invalid, Errors: errors);
        }

        var redirects = Redirects(input);
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, cancellationToken);
        var name = input.Name!.Trim();
        var reviewed = descriptor.RedirectUris.Select(uri => uri.OriginalString).ToHashSet(StringComparer.Ordinal);

        // What users see and where codes go must not change behind an approval. Disabled apps stay disabled.
        var needsReview = options.Value.DeveloperApps.RequireApproval
            && row.Status == OAuthDeveloperAppStatus.Active
            && (!string.Equals(name, row.Name, StringComparison.Ordinal) || !reviewed.SetEquals(redirects));
        descriptor.DisplayName = name;
        descriptor.RedirectUris.Clear();
        foreach (var redirect in redirects)
        {
            descriptor.RedirectUris.Add(new Uri(redirect));
        }

        if (needsReview)
        {
            // Saved before the new redirects go live, so a failure later never leaves them on an active app.
            row.Status = OAuthDeveloperAppStatus.PendingApproval;
            row.UpdatedAt = clock.GetUtcNow();
            await db.SaveChangesAsync(cancellationToken);
        }

        // The hashed secret round-trips unchanged, so OpenIddict keeps it as is.
        await applications.UpdateAsync(application, descriptor, cancellationToken);

        row.Name = descriptor.DisplayName;
        row.HomepageUrl = input.HomepageUrl!.Trim();
        row.Description = Description(input.Description);
        row.UpdatedAt = clock.GetUtcNow();
        await db.SaveChangesAsync(cancellationToken);
        return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.Succeeded, ToInfo(row, redirects));
    }

    public async Task<bool> DeleteAsync(Guid id, string ownerId, CancellationToken cancellationToken = default)
    {
        var row = await LoadAsync(id, ownerId, tracking: false, cancellationToken);
        if (row is null)
        {
            return false;
        }

        // Row first: if deleting the application fails, the gate already refuses it and cleanup removes it.
        await Apps.Where(app => app.Id == row.Id).ExecuteDeleteAsync(cancellationToken);
        if (await applications.FindByClientIdAsync(row.ClientId, cancellationToken) is { } application)
        {
            await DeleteApplicationAsync(applications, tokens, authorizations, application, cancellationToken);
        }

        return true;
    }

    public async Task<OAuthDeveloperAppResult> RotateSecretAsync(Guid id, string ownerId, CancellationToken cancellationToken = default)
    {
        var row = await LoadAsync(id, ownerId, tracking: true, cancellationToken);
        if (row is null || await applications.FindByClientIdAsync(row.ClientId, cancellationToken) is not { } application)
        {
            return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.NotFound);
        }

        if (!row.Confidential)
        {
            return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.NotConfidential);
        }

        var secret = NewSecret();
        await applications.UpdateAsync(application, secret, cancellationToken);
        var now = clock.GetUtcNow();
        row.SecretCreatedAt = now;
        row.UpdatedAt = now;
        await db.SaveChangesAsync(cancellationToken);
        var redirects = await RedirectsAsync(application, cancellationToken);
        return new OAuthDeveloperAppResult(OAuthDeveloperAppOutcome.Succeeded, ToInfo(row, redirects), secret);
    }

    public async Task<IReadOnlyList<OAuthDeveloperAppInfo>> ListByStatusAsync(
        OAuthDeveloperAppStatus status, CancellationToken cancellationToken = default)
    {
        var rows = await Apps.AsNoTracking()
            .Where(app => app.Status == status)
            .OrderBy(app => app.CreatedAt)
            .ToListAsync(cancellationToken);
        return await ToInfoAsync(rows, cancellationToken);
    }

    public async Task<bool> SetStatusAsync(Guid id, OAuthDeveloperAppStatus status, CancellationToken cancellationToken = default)
    {
        var row = await Apps.FirstOrDefaultAsync(app => app.Id == id, cancellationToken);
        if (row is null)
        {
            return false;
        }

        row.Status = status;
        row.UpdatedAt = clock.GetUtcNow();
        await db.SaveChangesAsync(cancellationToken);
        if (status != OAuthDeveloperAppStatus.Active
            && await applications.FindByClientIdAsync(row.ClientId, cancellationToken) is { } application
            && await applications.GetIdAsync(application, cancellationToken) is { Length: > 0 } applicationId)
        {
            await tokens.RevokeByApplicationIdAsync(applicationId, cancellationToken);
            await authorizations.RevokeByApplicationIdAsync(applicationId, cancellationToken);
        }

        return true;
    }

    public async ValueTask<bool> AllowsAsync(object application, CancellationToken cancellationToken)
    {
        if (await DeveloperAppIdAsync(applications, application, cancellationToken) is not { } id)
        {
            // A seeded or dynamically registered client.
            return true;
        }

        var clientId = await applications.GetClientIdAsync(application, cancellationToken);
        return await Apps.AnyAsync(
            app => app.Id == id && app.ClientId == clientId && app.Status == OAuthDeveloperAppStatus.Active,
            cancellationToken);
    }

    /// <summary>The row id a developer app's OpenIddict application points to, or <see langword="null"/> for other clients.</summary>
    internal static async ValueTask<Guid?> DeveloperAppIdAsync(
        IOpenIddictApplicationManager applications, object application, CancellationToken cancellationToken)
    {
        var settings = await applications.GetSettingsAsync(application, cancellationToken);
        if (!settings.TryGetValue(OAuthServerConstants.DeveloperAppSetting, out var raw))
        {
            return null;
        }

        // A marker that does not parse still marks a developer app. Guid.Empty matches no row, so it is refused.
        return Guid.TryParse(raw, CultureInfo.InvariantCulture, out var id) ? id : Guid.Empty;
    }

    internal static async Task DeleteApplicationAsync(
        IOpenIddictApplicationManager applications,
        IOpenIddictTokenManager tokens,
        IOpenIddictAuthorizationManager authorizations,
        object application,
        CancellationToken cancellationToken)
    {
        if (await applications.GetIdAsync(application, cancellationToken) is { Length: > 0 } applicationId)
        {
            // Revoke first so issued tokens stop working even if a later step fails.
            await tokens.RevokeByApplicationIdAsync(applicationId, cancellationToken);
            await authorizations.RevokeByApplicationIdAsync(applicationId, cancellationToken);
        }

        await applications.DeleteAsync(application, cancellationToken);
    }

    private async Task<OAuthDeveloperApp<TKey>?> LoadAsync(Guid id, string ownerId, bool tracking, CancellationToken cancellationToken)
    {
        if (!OAuthConsentService<TContext, TKey>.TryKey(ownerId, out var key))
        {
            return null;
        }

        var query = tracking ? Apps : Apps.AsNoTracking();
        return await query.FirstOrDefaultAsync(app => app.Id == id && app.OwnerId.Equals(key), cancellationToken);
    }

    /// <summary>One query for the redirect URIs of every listed app.</summary>
    private async Task<IReadOnlyList<OAuthDeveloperAppInfo>> ToInfoAsync(
        List<OAuthDeveloperApp<TKey>> rows, CancellationToken cancellationToken)
    {
        if (rows.Count == 0)
        {
            return [];
        }

        var clientIds = rows.Select(row => row.ClientId).ToList();
        var stored = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking()
            .Where(application => clientIds.Contains(application.ClientId!))
            .Select(application => new { application.ClientId, application.RedirectUris })
            .ToListAsync(cancellationToken);
        var redirects = stored.ToDictionary(
            application => application.ClientId!,
            application => ParseRedirects(application.RedirectUris),
            StringComparer.Ordinal);
        return rows
            .Select(row => ToInfo(row, redirects.GetValueOrDefault(row.ClientId) ?? []))
            .ToList();
    }

    private async Task<IReadOnlyList<string>> RedirectsAsync(object application, CancellationToken cancellationToken)
        => (await applications.GetRedirectUrisAsync(application, cancellationToken)).ToArray();

    private static IReadOnlyList<string> ParseRedirects(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static OAuthDeveloperAppInfo ToInfo(OAuthDeveloperApp<TKey> row, IReadOnlyList<string> redirects) => new(
        row.Id,
        row.ClientId,
        row.Name,
        row.HomepageUrl,
        row.Description,
        redirects,
        row.Confidential,
        row.Status,
        row.CreatedAt,
        row.UpdatedAt,
        row.SecretCreatedAt)
    {
        OwnerId = OAuthConsentService<TContext, TKey>.KeyToString(row.OwnerId),
    };

    private static string[] Redirects(OAuthDeveloperAppInput input)
        => input.RedirectUris!.Select(uri => uri.Trim()).Distinct(StringComparer.Ordinal).ToArray();

    private static string? Description(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    /// <summary>256 random bits, base64url.</summary>
    private static string NewSecret() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    private static Dictionary<string, string[]>? Validate(OAuthDeveloperAppInput input, bool confidential, OAuthDeveloperAppOptions limits)
    {
        var errors = new Dictionary<string, string[]>(StringComparer.Ordinal);
        var name = input.Name?.Trim();
        if (string.IsNullOrEmpty(name))
        {
            errors["name"] = ["Application name is required."];
        }
        else if (name.Length > OAuthDeveloperAppLimits.NameLength)
        {
            errors["name"] = [$"Application name is limited to {OAuthDeveloperAppLimits.NameLength} characters."];
        }

        if (!OAuthRedirects.IsHomepage(input.HomepageUrl?.Trim()))
        {
            errors["homepageUrl"] = ["Homepage URL must be an absolute http or https URL."];
        }

        if (input.Description?.Trim().Length > OAuthDeveloperAppLimits.DescriptionLength)
        {
            errors["description"] = [$"Description is limited to {OAuthDeveloperAppLimits.DescriptionLength} characters."];
        }

        var redirects = input.RedirectUris?.Select(uri => uri?.Trim()).ToArray() ?? [];
        if (redirects.Length == 0)
        {
            errors["redirectUris"] = ["At least one redirect URI is required."];
        }
        else if (redirects.Length > limits.MaxRedirectUris)
        {
            errors["redirectUris"] = [$"Redirect URIs are limited to {limits.MaxRedirectUris}."];
        }
        else
        {
            var invalid = redirects
                .Where(uri => !OAuthRedirects.IsAllowedDeveloperAppRedirect(uri, confidential))
                .Select(uri => confidential
                    ? $"'{uri}' must be https, or http on localhost, 127.0.0.1, or [::1], with no fragment."
                    : $"'{uri}' must be https, http on localhost, 127.0.0.1, or [::1], or a reverse-domain scheme such as com.example.app:/callback, with no fragment.")
                .ToArray();
            if (invalid.Length > 0)
            {
                errors["redirectUris"] = invalid;
            }
        }

        return errors.Count == 0 ? null : errors;
    }
}
