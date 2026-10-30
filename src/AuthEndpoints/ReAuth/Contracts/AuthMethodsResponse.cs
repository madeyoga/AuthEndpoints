namespace AuthEndpoints.ReAuth;

public sealed record AuthMethodsResponse(
    bool Password,
    bool Authenticator,
    bool RecoveryCodes,
    bool Passkeys,
    int PasskeyCount,
    bool EmailCode)
{
    /// <summary>
    /// Linked external providers the user can confirm their identity with.
    /// Empty when external step-up is off or no linked provider is allowed.
    /// </summary>
    public IReadOnlyList<ExternalAuthMethod> External { get; init; } = [];
}

/// <summary>A linked external provider available for step-up.</summary>
public sealed record ExternalAuthMethod(string Scheme, string? DisplayName);
