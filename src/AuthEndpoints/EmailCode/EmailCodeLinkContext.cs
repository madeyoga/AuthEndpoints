namespace AuthEndpoints.EmailCode;

public sealed class EmailCodeLinkContext
{
    public required string Token { get; init; }

    public required string LinkUri { get; init; }
}
