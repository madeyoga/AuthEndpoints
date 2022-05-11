using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Data;

public interface IRefreshTokenDbContext<TRefreshToken>
    where TRefreshToken : class
{
    DbSet<TRefreshToken>? RefreshTokens { get; set; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
