namespace AuthEndpoints.EmailCode;

public sealed class EmailCodeSendRequest
{
    public required string Email { get; init; }
}

public sealed record EmailCodeSendResponse(int ExpiresInSeconds, int ResendAfterSeconds);

public sealed class EmailCodeVerifyRequest
{
    public string? Email { get; init; }

    public string? Code { get; init; }

    public string? Token { get; init; }

    public string? TwoFactorCode { get; init; }

    public string? TwoFactorRecoveryCode { get; init; }
}
