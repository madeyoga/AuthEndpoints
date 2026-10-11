namespace AuthEndpoints.EmailCode;

public enum EmailCodePurpose
{
    SignIn,
    SignUp
}

public sealed class EmailCodeMessage<TUser>
    where TUser : class
{
    public required string Email { get; init; }

    public TUser? User { get; init; }

    public required string Code { get; init; }

    public string? LinkUrl { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    public required TimeSpan Lifetime { get; init; }

    public required EmailCodePurpose Purpose { get; init; }
}

/// <summary>
/// Sends the email-code sign-in message.
/// <see cref="EmailCodeMessage{TUser}.Code"/> and <see cref="EmailCodeMessage{TUser}.LinkUrl"/>
/// are raw, not HTML-encoded. Encode them when the template is HTML.
/// Queue the message and return quickly. A sender that waits on SMTP or HTTP
/// makes known addresses slower than unknown ones.
/// </summary>
public interface IEmailCodeSender<TUser>
    where TUser : class
{
    Task SendSignInCodeAsync(EmailCodeMessage<TUser> message, CancellationToken cancellationToken = default);
}
