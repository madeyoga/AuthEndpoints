using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Models;

public class TwoStepVerificationLoginRequest : LoginRequest
{
    [Required]
    public string? Provider { get; set; }

    public TwoStepVerificationLoginRequest(string username, string password) : base(username, password)
    {
    }
}
