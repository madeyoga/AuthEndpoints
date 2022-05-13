using AuthEndpoints.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Data;

public interface ITokenDbContext<TUser> where TUser : class
{
    DbSet<Token<TUser>>? Tokens { get; set; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
