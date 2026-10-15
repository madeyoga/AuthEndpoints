namespace AuthEndpoints.EmailCode;

public sealed class EmailCodeOptions
{
    public int CodeLength { get; set; } = 6;

    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    public int MaxAttempts { get; set; } = 5;

    public TimeSpan ResendCooldown { get; set; } = TimeSpan.FromSeconds(60);

    public int MaxSendsPerEmail { get; set; } = 5;

    public TimeSpan SendWindow { get; set; } = TimeSpan.FromHours(1);

    public int SendsPerIpPerMinute { get; set; } = 5;

    public bool AllowSignUp { get; set; }

    public bool RequireTwoFactor { get; set; } = true;

    public EmailCodeUnconfirmedAccounts UnconfirmedAccounts { get; set; } =
        EmailCodeUnconfirmedAccounts.ConfirmAndResetCredentials;

    public bool CountFailuresTowardLockout { get; set; } = true;

    public EmailCodeMagicLinkOptions MagicLink { get; set; } = new();

    /// <summary>
    /// Step-up codes for <c>POST /confirmIdentity</c>. Offered only when this user has no
    /// password, authenticator, or passkey. An external login is not a stronger factor.
    /// </summary>
    public EmailCodeReAuthOptions ReAuth { get; set; } = new();

    /// <summary>
    /// Requires a real email-code sender in every environment except Development.
    /// </summary>
    public bool RequireSenderOutsideDevelopment { get; set; } = true;
}

public sealed class EmailCodeReAuthOptions
{
    public bool Enabled { get; set; } = true;

    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(5);
}

public sealed class EmailCodeMagicLinkOptions
{
    public bool Enabled { get; set; }

    public string? LinkUri { get; set; }

    public IList<string> AllowedOrigins { get; set; } = new List<string>();

    public Func<EmailCodeLinkContext, string>? BuildLinkUrl { get; set; }
}

public enum EmailCodeUnconfirmedAccounts
{
    ConfirmAndResetCredentials,
    Reject
}
