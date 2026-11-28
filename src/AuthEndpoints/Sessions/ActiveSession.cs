namespace AuthEndpoints.Sessions;

/// <summary>
/// One signed-in device or browser. Created on each successful sign-in when
/// <see cref="ActiveSessionServiceCollectionExtensions.AddActiveSessions{TUser}(Microsoft.Extensions.DependencyInjection.IServiceCollection, System.Action{ActiveSessionOptions}?)"/>
/// is on. A JWT session follows its refresh-token family across rotations.
/// </summary>
public class ActiveSession
{
    /// <summary>The longest <see cref="UserAgent"/> stored. Longer values are truncated.</summary>
    public const int MaxUserAgentLength = 512;

    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public required string UserId { get; set; }

    /// <summary>User-Agent of the sign-in request, truncated to <see cref="MaxUserAgentLength"/> characters.</summary>
    public string? UserAgent { get; set; }

    /// <summary>Security stamp at sign-in. A session whose stamp no longer matches the user has ended.</summary>
    public required string SecurityStamp { get; set; }

    public DateTime CreatedAt { get; set; }

    /// <summary>Last time the session was used. Updated at most once per <see cref="ActiveSessionOptions.LastSeenUpdateInterval"/>.</summary>
    public DateTime LastSeenAt { get; set; }

    /// <summary>When the cookie or refresh-token family stops being accepted.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>Set when the session was signed out, revoked, or invalidated.</summary>
    public DateTime? RevokedAt { get; set; }
}
