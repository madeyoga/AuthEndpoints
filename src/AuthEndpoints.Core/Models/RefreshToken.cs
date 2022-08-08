namespace AuthEndpoints.Core.Models;

/// <summary>
/// Refresh token model
/// </summary>
public class RefreshToken
{
    public int Id { get; set; }
    public string? Token { get; set; }
}
