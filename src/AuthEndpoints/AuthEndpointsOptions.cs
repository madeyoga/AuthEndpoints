namespace AuthEndpoints;

/// <summary>
/// Runtime settings shared by every AuthEndpoints route.
/// <c>AddAuthEndpoints</c> configures it. A host that composes building blocks sets it with
/// <c>services.Configure&lt;AuthEndpointsOptions&gt;</c>.
/// </summary>
public sealed class AuthEndpointsOptions
{
    /// <summary>SPA redirect after browser <c>GET</c> confirm-email.</summary>
    public EmailConfirmationOptions EmailConfirmation { get; set; } = new();

    /// <summary>
    /// When true (default), <c>AddAuthEndpoints</c> requires a real <c>IEmailSender&lt;TUser&gt;</c> in Production
    /// (not the Identity no-op). Development is not checked.
    /// </summary>
    public bool RequireEmailSenderInProduction { get; set; } = true;
}

public sealed class EmailConfirmationOptions
{
    /// <summary>
    /// Frontend URI after <c>GET</c> confirm-email (absolute <c>https://</c>, or a rooted path).
    /// Empty or null keeps the plain-text / 401 response.
    /// </summary>
    public string? ConfirmEmailRedirectUri { get; set; }

    /// <summary>
    /// Origins such as <c>https://app.example.com</c> allowed for an absolute <see cref="ConfirmEmailRedirectUri"/>.
    /// A rooted path does not need an entry.
    /// </summary>
    public IList<string> AllowedRedirectOrigins { get; set; } = new List<string>();
}

/// <summary>
/// Lifetime for the ReAuth cookie and header <c>reauthToken</c>.
/// Both use this value for the same confirm. The cookie is not persistent
/// and does not slide. Valid range: 1 minute through 60 minutes.
/// Set it with <c>services.Configure&lt;AuthEndpointsReAuthOptions&gt;</c>.
/// </summary>
public sealed class AuthEndpointsReAuthOptions
{
    /// <summary>
    /// How long a successful <c>confirmIdentity</c> stays valid.
    /// Default: 5 minutes. Applies to cookie <c>ExpireTimeSpan</c>,
    /// ticket <c>ExpiresUtc</c>, and <c>reauthToken</c> expiry.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(5);
}
