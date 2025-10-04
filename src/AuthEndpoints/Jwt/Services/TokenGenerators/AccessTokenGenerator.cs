using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Jwt;

public class AccessTokenGenerator : IAccessTokenGenerator
{
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly SimpleJwtOptions _options;

    public AccessTokenGenerator(JwtSecurityTokenHandler tokenHandler, IOptions<SimpleJwtOptions> options)
    {
        _tokenHandler = tokenHandler;
        _options = options.Value;
    }

    public string GenerateAccessToken(ClaimsPrincipal user)
    {
        var credentials = _options.SigningOptions.ToSigningCredentials();
        var header = new JwtHeader(credentials);
        var payload = new JwtPayload(
            _options.Issuer,
            _options.Audience,
            user.Claims,
            DateTime.UtcNow,
            DateTime.UtcNow.Add(_options.AccessTokenLifetime)
        );
        return _tokenHandler.WriteToken(new JwtSecurityToken(header, payload));
    }
}
