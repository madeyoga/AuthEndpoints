using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Core.Services;

public class RefreshTokenGenerator<TUser> : IRefreshTokenGenerator<TUser>
    where TUser : class
{
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly AuthEndpointsOptions _options;
    private readonly IClaimsProvider<TUser> _claimsProvider;

    public RefreshTokenGenerator(JwtSecurityTokenHandler tokenHandler, IOptions<AuthEndpointsOptions> options, IClaimsProvider<TUser> claimsProvider)
    {
        _tokenHandler = tokenHandler;
        _options = options.Value;
        _claimsProvider = claimsProvider;
    }

    public string GenerateRefreshToken(TUser user)
    {
        var signingOptions = _options.RefreshSigningOptions!;
        var credentials = new SigningCredentials(signingOptions.SigningKey, signingOptions.Algorithm);
        var header = new JwtHeader(credentials);
        var payload = new JwtPayload(
            _options.Issuer!,
            _options.Audience!,
            _claimsProvider.provideRefreshClaims(user),
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(signingOptions.ExpirationMinutes)
        );
        return _tokenHandler.WriteToken(new JwtSecurityToken(header, payload));
    }
}
