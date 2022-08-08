using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Core.Contracts;

/// <summary>
/// The dto used for email confirmation request
/// </summary>
public class ConfirmEmailRequest
{
    [Required]
    public string? Identity { get; set; }
    [Required]
    public string? Token { get; set; }
}
