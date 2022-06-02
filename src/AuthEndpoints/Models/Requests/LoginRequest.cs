using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Models;

/// <summary>
/// The dto used for login request
/// </summary>
public class LoginRequest
{
    [Required]
    public string Username { get; set; }

    [Required]
    public string Password { get; set; }

    public LoginRequest(string username, string password)
    {
        Username = username;
        Password = password;
    }
}
