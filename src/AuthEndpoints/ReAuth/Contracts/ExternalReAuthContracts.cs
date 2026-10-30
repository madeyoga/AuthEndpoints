namespace AuthEndpoints.ReAuth;

/// <summary>Body for <c>POST /confirmIdentity/external/{provider}</c>.</summary>
public sealed class ExternalReAuthStartRequest
{
    /// <summary>Where to send the browser after the provider sign-in. Checked against the external return URL allowlist.</summary>
    public string? ReturnUrl { get; init; }
}

/// <summary>Response for <c>POST /confirmIdentity/external/{provider}</c>.</summary>
public sealed class ExternalReAuthStartResponse
{
    /// <summary>Navigate the browser here to start the provider sign-in.</summary>
    public required string RedirectUrl { get; init; }
}

/// <summary>Body for <c>POST /confirmIdentity/external/complete</c>.</summary>
public sealed class ExternalReAuthCompleteRequest
{
    /// <summary>The one-time <c>reauthCode</c> from the step-up return URL.</summary>
    public string? Code { get; init; }
}
