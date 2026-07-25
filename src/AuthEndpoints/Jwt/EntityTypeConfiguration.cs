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
    public static ModelBuilder UseRefreshToken(this ModelBuilder builder)
    {
        var entityBuilder = builder.Entity<RefreshToken>();

        entityBuilder.ToTable("AuthEndpointsRefreshTokens", "AuthEndpoints");
        entityBuilder.HasKey(e => e.Id);
        entityBuilder.Property(e => e.TokenHash).IsRequired();
        entityBuilder.HasIndex(e => e.TokenHash).IsUnique();
        entityBuilder.Property(e => e.FamilyId).IsRequired();
        entityBuilder.Property(e => e.SecurityStamp).IsRequired();
        entityBuilder.Ignore(e => e.Token);

        return builder;
    }
}
