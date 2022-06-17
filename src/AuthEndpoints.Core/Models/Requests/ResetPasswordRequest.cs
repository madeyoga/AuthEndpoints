using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Models;

/// <summary>
/// The dto used for reset password request
/// </summary>
public class ResetPasswordRequest
{
    [Required]
    [EmailAddress]
    public string? Email { get; set; }
}
