using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Models;

public class TwoStepVerificationConfirmRequest
{
    [Required]
    public string? Email { get; set; }
    [Required]
    public string? Provider { get; set; }
    [Required]
    public string? Token { get; set; }
}
