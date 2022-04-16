namespace AuthEndpoints.Jwt.Models.Requests;

using System.ComponentModel.DataAnnotations;

public class RegisterRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    public string Username { get; set; }

    [Required]
    public string Password { get; set; }

    [Required]
    public string ConfirmPassword { get; set; }

    public RegisterRequest(string email, string username, string password, string confirmPassword)
    {
        Email = email;
        Username = username;
        Password = password;
        ConfirmPassword = confirmPassword;
    }
}
