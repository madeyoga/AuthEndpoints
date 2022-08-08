using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Core.Contracts;

/// <summary>
/// the dto used for refresh request
/// </summary>
public class RefreshRequest
{
    [Required]
    public string? RefreshToken { get; set; }
}
