using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.SimpleJwt;

public class RefreshTokenGenerator<TContext> : IRefreshTokenService
    where TContext : DbContext
{
    private readonly IDataProtector _dataProtector;
    private readonly TContext dbContext;

    public RefreshTokenGenerator(IDataProtectionProvider dataProtectionProvider, TContext dbContext)
    {
        _dataProtector = dataProtectionProvider.CreateProtector("authendpoints_simplejwt_refreshtoken");
        this.dbContext = dbContext;
    }

    public string GenerateRefreshToken(ClaimsPrincipal user)
    {
        var code = new SimpleJwtRefreshTokenData
        {
            NameIdentifier = user.FindFirstValue(ClaimTypes.NameIdentifier),
            Name = user.FindFirstValue(ClaimTypes.Name),
            Expiry = DateTime.Now.AddHours(24),
        };

        string token = _dataProtector.Protect(JsonSerializer.Serialize(code));
        dbContext.Set<SimpleJwtRefreshToken>().Add(new SimpleJwtRefreshToken
        {
            Token = token,
        });
        dbContext.SaveChanges();
        return token;
    }

    public ClaimsPrincipal GetTokenClaimsAsync()
    {
        throw new NotImplementedException();
    }
}

internal class SimpleJwtRefreshTokenData
{
    public string NameIdentifier { get; set; }
    public string Name { get; set; }
    public DateTime Expiry { get; set; }
}
