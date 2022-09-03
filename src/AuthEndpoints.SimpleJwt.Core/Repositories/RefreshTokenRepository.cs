using AuthEndpoints.SimpleJwt.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.SimpleJwt.Core;

public class RefreshTokenRepository<TContext> : IRefreshTokenRepository where TContext : DbContext
{
    private readonly TContext _context;

    public RefreshTokenRepository(TContext context)
    {
        _context = context;
    }

    public async Task AddAsync(RefreshToken refreshToken)
    {
        await _context.AddAsync(refreshToken);
    }

    public async Task<RefreshToken?> GetByIdAsync(int id)
    {
        RefreshToken? result = await _context.Set<RefreshToken>().FindAsync(id);
        return result;
    }

    public async Task<RefreshToken?> GetByTokenAsync(string token)
    {
        RefreshToken? result = await _context.Set<RefreshToken>().Where((t) => t.Token == token).FirstOrDefaultAsync();
        return result;
    }

    public async Task<int> SaveChangesAsync()
    {
        return await _context.SaveChangesAsync();
    }
}
