using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Jwt.Data;

public class JwtDbContext<TRefreshToken> : DbContext
    where TRefreshToken : class
{
    public DbSet<TRefreshToken>? RefreshTokens { get; set; }
}
