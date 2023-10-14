using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// the dto used for registration request
/// </summary>
public class SimpleJwtRegisterRequest
{
    [Required]
    [EmailAddress]
    public string? Email { get; set; }

    [Required]
    public string? Username { get; set; }

    [Required]
    public string? Password { get; set; }

    [Required]
    public string? ConfirmPassword { get; set; }
}
