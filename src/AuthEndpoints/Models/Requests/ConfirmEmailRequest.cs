namespace AuthEndpoints.Models;

/// <summary>
/// The dto used for email confirmation request
/// </summary>
public class ConfirmEmailRequest
{
    public string Identity { get; set; }
    public string Token { get; set; }
}
