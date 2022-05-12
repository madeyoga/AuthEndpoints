using AuthEndpoints.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Data;

public interface IAuthDbContext<TUser, TRefreshToken>
    where TUser : class
    where TRefreshToken : class
{
    DbSet<Token<TUser>>? Tokens { get; set; }
    DbSet<TRefreshToken>? RefreshTokens { get; set; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
