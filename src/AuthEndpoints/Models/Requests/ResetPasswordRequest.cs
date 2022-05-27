using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Models;

public class ResetPasswordRequest
{
    [Required]
    [EmailAddress]
    public string? Email { get; set; }
}
