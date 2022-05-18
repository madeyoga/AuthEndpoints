namespace AuthEndpoints.Models.Requests;

public class SetUsernameRequest
{
    public string? NewUsername { get; set; }
    public string? CurrentPassword { get; set; }
}
