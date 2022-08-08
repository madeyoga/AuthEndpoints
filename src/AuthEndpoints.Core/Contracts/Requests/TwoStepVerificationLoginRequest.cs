using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Core.Contracts;

public class TwoStepVerificationLoginRequest : LoginRequest
{
    [Required]
    public string? Provider { get; set; }
}
