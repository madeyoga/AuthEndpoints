using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt.Core.Services;

public class AccessTokenGenerator : IAccessTokenGenerator
{
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly SimpleJwtOptions _options;
    private readonly IClaimsProvider _claimsProvider;

    public AccessTokenGenerator(JwtSecurityTokenHandler tokenHandler, IOptions<SimpleJwtOptions> options, IClaimsProvider claimsProvider)
    {
        _tokenHandler = tokenHandler;
        _options = options.Value;
        _claimsProvider = claimsProvider;
    }

    public string GenerateAccessToken(ClaimsPrincipal user)
    {
        var signingOptions = _options.AccessSigningOptions!;
        var credentials = new SigningCredentials(signingOptions.SigningKey, signingOptions.Algorithm);
        var header = new JwtHeader(credentials);
        var payload = new JwtPayload(
            _options.Issuer!,
            _options.Audience!,
            _claimsProvider.ProvideAccessClaims(user),
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(signingOptions.ExpirationMinutes)
        );
        return _tokenHandler.WriteToken(new JwtSecurityToken(header, payload));
    }
}
