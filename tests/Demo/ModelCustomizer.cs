using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Demo;

public static class EntityFrameworkCoreHelpers
{
    public static ModelBuilder UseDemo(this ModelBuilder builder)
    {
        builder.Entity<Blog>();

        return builder;
    }

    public static DbContextOptionsBuilder UseDemo(this DbContextOptionsBuilder builder)
    {
        builder.ReplaceService<IModelCustomizer, DemoEFCoreCustomizer>();
        return builder;
    }
}

public sealed class DemoEFCoreCustomizer : RelationalModelCustomizer
{
    public DemoEFCoreCustomizer(ModelCustomizerDependencies dependencies) : base(dependencies)
    {
    }

    public override void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder, nameof(modelBuilder));
        ArgumentNullException.ThrowIfNull(context, nameof(context));

        modelBuilder.UseDemo();

        base.Customize(modelBuilder, context);
    }
}
