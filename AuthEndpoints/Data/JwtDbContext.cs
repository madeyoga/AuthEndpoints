using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Data;

public class JwtDbContext<TRefreshToken> : DbContext
    where TRefreshToken : class
{
    public DbSet<TRefreshToken>? RefreshTokens { get; set; }
}
