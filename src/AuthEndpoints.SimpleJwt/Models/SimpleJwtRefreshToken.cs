using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// Refresh token model
/// </summary>
public class SimpleJwtRefreshToken
{
    [Key]
    public int Id { get; set; }
    public string? Token { get; set; }
}
