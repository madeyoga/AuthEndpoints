namespace AuthEndpoints.Identity;

public class ConfirmIdentityRequest
{
    public string? Password { get; init; }
    public string? TwoFactorCode { get; init; }
}
