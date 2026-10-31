using AuthEndpoints.Jwt;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthEndpoints.Sessions;

internal sealed class ActiveSessionConfiguration : IEntityTypeConfiguration<ActiveSession>
{
    public void Configure(EntityTypeBuilder<ActiveSession> builder)
    {
        builder.ToTable("AuthEndpointsActiveSessions", "AuthEndpoints");
        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasMaxLength(64);
        builder.Property(e => e.UserId).IsRequired();
        builder.HasIndex(e => e.UserId);
        builder.Property(e => e.UserAgent).HasMaxLength(ActiveSessionStore.MaxUserAgentLength);
        builder.Property(e => e.SecurityStamp).IsRequired();
        builder.HasIndex(e => e.ExpiresAt);
    }
}

public static class ActiveSessionModelBuilderExtensions
{
    internal const string RefreshTokenSessionIdProperty = "SessionId";

    /// <summary>
    /// Maps the session entity (<c>AuthEndpoints.AuthEndpointsActiveSessions</c>) for
    /// <see cref="ActiveSessionServiceCollectionExtensions.AddActiveSessions{TUser, TContext}(Microsoft.Extensions.DependencyInjection.IServiceCollection, System.Action{ActiveSessionOptions}?)"/>.
    /// With JWT, call <see cref="EntityFrameworkCoreHelpers.UseRefreshToken"/> first: this adds a nullable
    /// <c>SessionId</c> column to the refresh-token table.
    /// </summary>
    public static ModelBuilder UseActiveSessions(this ModelBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.ApplyConfiguration(new ActiveSessionConfiguration());

        if (builder.Model.FindEntityType(typeof(RefreshToken)) is not null)
        {
            builder.Entity<RefreshToken>(entity =>
            {
                entity.Property<string?>(RefreshTokenSessionIdProperty).HasMaxLength(64);
                entity.HasIndex(RefreshTokenSessionIdProperty);
            });
        }

        return builder;
    }
}
