using AuthEndpoints.Demo.Models;
using AuthEndpoints.Jwt.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Demo.Data;

public class MyDbContext
    : DbContext, IAuthenticationDbContext<RefreshToken>
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }

    public DbSet<User>? Users { get; set; }
    //public DbSet<Slot>? Slots { get; set; }
    //public DbSet<Tourney>? Tourneys { get; set; }
    //public DbSet<TournamentStage>? TournamentStages { get; set; }
    //public DbSet<Match>? Matches { get; set; }
    //public DbSet<Game>? Games { get; set; }
    //public DbSet<OfficialTeam>? OfficialTeams { get; set; }
    //public DbSet<TeamMembership>? TeamMemberships { get; set; }
    public DbSet<RefreshToken>? RefreshTokens { get; set; }
}
