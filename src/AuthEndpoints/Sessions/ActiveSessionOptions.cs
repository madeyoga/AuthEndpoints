namespace AuthEndpoints.Sessions;

/// <summary>
/// Options for active session tracking.
/// </summary>
public sealed class ActiveSessionOptions
{
    /// <summary>
    /// Minimum time between last-seen writes for one session. Default 5 minutes.
    /// </summary>
    public TimeSpan LastSeenUpdateInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long a cookie request may trust the last session check before reading the session record
    /// again. A revoke made on another server can take up to this long to apply. Zero checks every request.
    /// Default 30 seconds.
    /// </summary>
    public TimeSpan RevalidationInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How often expired and ended session records are deleted. Default 1 hour.
    /// </summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromHours(1);
}
