using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthEndpoints.Jwt;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("AuthEndpointsRefreshTokens", "AuthEndpoints");
        builder.HasKey(e => e.Id);
        builder.Property(e => e.TokenHash).IsRequired();
        builder.HasIndex(e => e.TokenHash).IsUnique();
        builder.Property(e => e.FamilyId).IsRequired();
        builder.Property(e => e.SecurityStamp).IsRequired();
        builder.Ignore(e => e.Token);
    }
}

public static class EntityFrameworkCoreHelpers
{
    /// <summary>
    /// Maps the JWT refresh-token entity (<c>AuthEndpoints.AuthEndpointsRefreshTokens</c>).
    /// Call from your <c>DbContext.OnModelCreating</c> when using <c>AddJwtEndpoints</c> / <c>MapJwtAuthEndpoints</c>.
    /// </summary>
    public static ModelBuilder UseRefreshToken(this ModelBuilder builder)
    {
        builder.ApplyConfiguration(new RefreshTokenConfiguration());
        return builder;
    }
}
