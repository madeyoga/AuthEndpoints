using Microsoft.EntityFrameworkCore;
// using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthEndpoints.Jwt;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("AuthEndpointsRefreshTokens", "AuthEndpoints");
        builder.HasKey(e => e.Id);
        builder.Property(e => e.Token).IsRequired();
    }
}

public static class EntityFrameworkCoreHelpers
{
    public static ModelBuilder UseRefreshToken(this ModelBuilder builder)
    {
        var entityBuilder = builder.Entity<RefreshToken>();

        entityBuilder.ToTable("AuthEndpointsRefreshTokens", "AuthEndpoints");
        entityBuilder.HasKey(e => e.Id);
        entityBuilder.Property(e => e.Token).IsRequired();

        return builder;
    }

    // public static DbContextOptionsBuilder UseSimpleJwtEntities(this DbContextOptionsBuilder builder)
    // {
    //     builder.ReplaceService<IModelCustomizer, SimpleJwtEFCoreCustomizer>();
    //     return builder;
    // }
}

// public sealed class SimpleJwtEFCoreCustomizer : RelationalModelCustomizer
// {
//     public SimpleJwtEFCoreCustomizer(ModelCustomizerDependencies dependencies) : base(dependencies)
//     {
//     }

//     public override void Customize(ModelBuilder modelBuilder, DbContext context)
//     {
//         ArgumentNullException.ThrowIfNull(modelBuilder, nameof(modelBuilder));
//         ArgumentNullException.ThrowIfNull(context, nameof(context));

//         modelBuilder.UseSimpleJwtEntities();

//         base.Customize(modelBuilder, context);
//     }
// }
