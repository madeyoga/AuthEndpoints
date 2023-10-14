using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Users;

public class TwoStepVerificationLoginRequest
{
    [Required]
    public string? Username { get; set; }

    [Required]
    public string? Password { get; set; }
    [Required]
    public string? Provider { get; set; }
}
