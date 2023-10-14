using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// the dto used for refresh request
/// </summary>
public class SimpleJwtRefreshTokenRequest
{
    [Required]
    public string? RefreshToken { get; set; }
}
