namespace AuthEndpoints.OpenIddict;

/// <summary>
/// One pending consent. <c>/connect/authorize</c> stores it and sends the browser to the host's consent page
/// with its id. It can be approved or denied once, by the user who started it, before it expires.
/// </summary>
/// <typeparam name="TKey">The Identity user key type.</typeparam>
public class OAuthRequest<TKey>
    where TKey : IEquatable<TKey>
{
    public Guid Id { get; init; } = Guid.CreateVersion7();

    public TKey UserId { get; set; } = default!;

    public required string ClientId { get; set; }

    public required string ClientName { get; set; }

    public required string RedirectUri { get; set; }

    /// <summary>Host of <see cref="RedirectUri"/>, plus the port when it is not the default. Show it on the consent page.</summary>
    public required string RedirectHost { get; set; }

    public required string CodeChallenge { get; set; }

    /// <summary>Space-separated scopes that will be granted.</summary>
    public required string Scope { get; set; }

    public string? State { get; set; }

    /// <summary>Resource indicator stamped into the access token audience.</summary>
    public required string Resource { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}
