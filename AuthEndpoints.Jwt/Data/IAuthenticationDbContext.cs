using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Jwt.Data;

public interface IAuthenticationDbContext<TRefreshToken>
    where TRefreshToken : class
{
    DbSet<TRefreshToken>? RefreshTokens { get; set; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
