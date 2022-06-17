using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.Models;

/// <summary>
/// the dto used for refresh request
/// </summary>
public class RefreshRequest
{
    [Required]
    public string RefreshToken { get; set; }

    public RefreshRequest(string refreshToken)
    {
        RefreshToken = refreshToken;
    }
}