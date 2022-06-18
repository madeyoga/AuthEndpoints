namespace AuthEndpoints.Models;

/// <summary>
/// the dto used for set username request
/// </summary>
public class SetUsernameRequest
{
    public string? NewUsername { get; set; }
    public string? CurrentPassword { get; set; }
}