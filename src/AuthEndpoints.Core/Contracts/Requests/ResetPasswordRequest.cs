using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Core.Contracts;

/// <summary>
/// The dto used for reset password request
/// </summary>
public class ResetPasswordRequest
{
    [Required]
    [EmailAddress]
    public string? Email { get; set; }
}
