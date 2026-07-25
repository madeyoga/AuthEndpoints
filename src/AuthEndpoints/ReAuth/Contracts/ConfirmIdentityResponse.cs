namespace AuthEndpoints.ReAuth;

public sealed class ConfirmIdentityResponse
{
    /// <summary>
    /// Short-lived step-up token for API clients. Send it as the
    /// <c>X-AuthEndpoints-Reauth</c> header on sensitive requests.
    /// Cookie clients also receive the <c>AuthEndpoints.ReAuth</c> cookie.
    /// </summary>
    public required string ReauthToken { get; init; }
}
