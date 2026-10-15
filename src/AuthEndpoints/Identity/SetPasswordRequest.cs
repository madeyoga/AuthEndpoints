namespace AuthEndpoints.Identity;

/// <summary>
/// Body for <c>POST /manage/password</c>. Sets a password only when the account has none.
/// </summary>
public sealed class SetPasswordRequest
{
    public string? NewPassword { get; init; }
}
