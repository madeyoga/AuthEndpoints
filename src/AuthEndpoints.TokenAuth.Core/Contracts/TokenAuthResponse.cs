namespace AuthEndpoints.TokenAuth.Core;

/// <summary>
/// the dto used to send an authenticated user response containing bearer token.
/// </summary>
public class TokenAuthResponse
{
    public string? AuthToken { get; set; }
}
