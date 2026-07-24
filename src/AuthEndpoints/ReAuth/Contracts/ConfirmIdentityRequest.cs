namespace AuthEndpoints.ReAuth;

public sealed class ConfirmIdentityRequest
{
    public string? Password { get; init; }
    public string? TwoFactorCode { get; init; }
    public string? TwoFactorRecoveryCode { get; init; }
    public string? CredentialJson { get; init; }
}
