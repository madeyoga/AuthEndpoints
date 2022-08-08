using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Core.Contracts;

/// <summary>
/// The dto used for login request
/// </summary>
public class LoginRequest
{
    [Required]
    public string? Username { get; set; }

    [Required]
    public string? Password { get; set; }
}
