namespace AuthEndpoints.Models;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// the dto used for refresh jwt request
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
