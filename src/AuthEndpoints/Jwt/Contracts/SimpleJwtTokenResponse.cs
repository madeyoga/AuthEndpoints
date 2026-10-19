using System.Text.Json.Serialization;

namespace AuthEndpoints.Jwt;

public class SimpleJwtTokenResponse
{
    public required string AccessToken { get; set; }
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// Raw refresh token. Present when <see cref="JwtSessionOptions.RefreshTokenTransport"/>
    /// is <see cref="RefreshTokenTransport.Body"/>. Omitted from JSON when null.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RefreshToken { get; set; }
}
