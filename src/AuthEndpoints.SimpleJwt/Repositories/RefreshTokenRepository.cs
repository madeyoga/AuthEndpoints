using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.SimpleJwt;

public class RefreshTokenRepository<TContext> : IRefreshTokenRepository where TContext : DbContext
{
    private readonly TContext _context;

    public RefreshTokenRepository(TContext context)
    {
        _context = context;
    }

    public async Task AddAsync(SimpleJwtRefreshToken refreshToken)
    {
        await _context.AddAsync(refreshToken);
    }

    public async Task<SimpleJwtRefreshToken?> GetByIdAsync(int id)
    {
        SimpleJwtRefreshToken? result = await _context.Set<SimpleJwtRefreshToken>().FindAsync(id);
        return result;
    }

    public async Task<SimpleJwtRefreshToken?> GetByTokenAsync(string token)
    {
        SimpleJwtRefreshToken? result = await _context.Set<SimpleJwtRefreshToken>().Where((t) => t.Token == token).FirstOrDefaultAsync();
        return result;
    }

    public async Task<int> SaveChangesAsync()
    {
        return await _context.SaveChangesAsync();
    }
}
