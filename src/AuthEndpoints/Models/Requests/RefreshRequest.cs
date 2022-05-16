namespace AuthEndpoints.Models.Requests;

using System.ComponentModel.DataAnnotations;

public class RefreshRequest
{
    [Required]
    public string RefreshToken { get; set; }

    public RefreshRequest(string refreshToken)
    {
        RefreshToken = refreshToken;
    }
}
