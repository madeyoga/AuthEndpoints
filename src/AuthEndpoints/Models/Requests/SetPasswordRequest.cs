using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Models;

/// <summary>
/// the dto used for set password request
/// </summary>
public class SetPasswordRequest
{
    [Required]
    public string? CurrentPassword { get; set; }

    [Required]
    public string? NewPassword { get; set; }

    [Required]
    public string? ConfirmNewPassword { get; set; }
}