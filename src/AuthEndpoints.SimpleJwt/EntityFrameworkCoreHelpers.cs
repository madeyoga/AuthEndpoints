using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace AuthEndpoints.SimpleJwt;

public static class EntityFrameworkCoreHelpers
{
    public static ModelBuilder UseSimpleJwtEntities(this ModelBuilder builder)
    {
        builder.Entity<SimpleJwtRefreshToken>();

        return builder;
    }

    public static DbContextOptionsBuilder UseSimpleJwtEntities(this DbContextOptionsBuilder builder)
    {
        builder.ReplaceService<IModelCustomizer, SimpleJwtEFCoreCustomizer>();
        return builder;
    }
}

public sealed class SimpleJwtEFCoreCustomizer : RelationalModelCustomizer
{
    public SimpleJwtEFCoreCustomizer(ModelCustomizerDependencies dependencies) : base(dependencies)
    {
    }

    public override void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder, nameof(modelBuilder));
        ArgumentNullException.ThrowIfNull(context, nameof(context));

        modelBuilder.UseSimpleJwtEntities();

        base.Customize(modelBuilder, context);
    }
}
