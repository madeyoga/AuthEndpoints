using System.Text.Json.Serialization;

namespace AuthEndpoints.OpenIddict;

/// <summary>Whether a developer app may sign users in.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<OAuthDeveloperAppStatus>))]
public enum OAuthDeveloperAppStatus
{
    /// <summary>The app can sign users in.</summary>
    Active,

    /// <summary>Waiting for an admin to approve it. Authorize and token requests are rejected.</summary>
    PendingApproval,

    /// <summary>Turned off by an admin. Authorize and token requests are rejected and its tokens were revoked.</summary>
    Disabled,
}

/// <summary>
/// An OAuth client that a signed-in user registered and owns. The OpenIddict application with the same
/// <see cref="ClientId"/> holds the redirect URIs, permissions, and the hashed client secret.
/// </summary>
/// <typeparam name="TKey">The Identity user key type.</typeparam>
public class OAuthDeveloperApp<TKey>
    where TKey : IEquatable<TKey>
{
    public Guid Id { get; init; } = Guid.CreateVersion7();

    /// <summary>The user who registered the app.</summary>
    public TKey OwnerId { get; set; } = default!;

    public required string ClientId { get; set; }

    public required string Name { get; set; }

    public required string HomepageUrl { get; set; }

    public string? Description { get; set; }

    /// <summary><see langword="true"/> for a client with a secret. Fixed at creation.</summary>
    public bool Confidential { get; set; }

    public OAuthDeveloperAppStatus Status { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    /// <summary>When the current client secret was generated. <see langword="null"/> for a public client.</summary>
    public DateTimeOffset? SecretCreatedAt { get; set; }
}
