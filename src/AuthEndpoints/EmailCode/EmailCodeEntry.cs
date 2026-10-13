namespace AuthEndpoints.EmailCode;

public enum EmailCodeRowPurpose
{
    SignIn = 0,
    ReAuth = 1
}

public class EmailCodeEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    public required string EmailHash { get; set; }

    public EmailCodeRowPurpose Purpose { get; set; } = EmailCodeRowPurpose.SignIn;

    public string? UserId { get; set; }

    public required string CodeHash { get; set; }

    public string? LinkTokenHash { get; set; }

    public string? SecurityStamp { get; set; }

    public string? SignupEmail { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime ExpiresAt { get; set; }

    public int Attempts { get; set; }

    public DateTime? ConsumedAt { get; set; }

    public DateTime? SupersededAt { get; set; }
}
