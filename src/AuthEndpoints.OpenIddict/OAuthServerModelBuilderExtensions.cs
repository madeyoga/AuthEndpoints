using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;

namespace AuthEndpoints.OpenIddict;

public static class OAuthServerModelBuilderExtensions
{
    /// <summary>
    /// Adds the OpenIddict entities and the <c>OAuthRequests</c> pending-consent table, with a cascading
    /// foreign key to <typeparamref name="TUser"/>. Call it from <c>OnModelCreating</c> after <c>base.OnModelCreating</c>,
    /// then add a migration.
    /// </summary>
    public static ModelBuilder UseAuthEndpointsOpenIddict<TUser, TKey>(this ModelBuilder builder)
        where TUser : class
        where TKey : IEquatable<TKey>
    {
        builder.UseAuthEndpointsOpenIddict<TKey>();
        builder.Entity<OAuthRequest<TKey>>()
            .HasOne<TUser>()
            .WithMany()
            .HasForeignKey(row => row.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        return builder;
    }

    /// <summary>
    /// Adds the OpenIddict entities and the <c>OAuthRequests</c> pending-consent table without a user foreign key.
    /// </summary>
    public static ModelBuilder UseAuthEndpointsOpenIddict<TKey>(this ModelBuilder builder)
        where TKey : IEquatable<TKey>
    {
        builder.UseOpenIddict();
        builder.Entity<OpenIddictEntityFrameworkCoreToken>()
            .Property(token => token.ReferenceId)
            .HasMaxLength(OAuthServerConstants.ReferenceTokenLength);
        Configure(builder.Entity<OAuthRequest<TKey>>());
        return builder;
    }

    private static void Configure<TKey>(EntityTypeBuilder<OAuthRequest<TKey>> builder)
        where TKey : IEquatable<TKey>
    {
        builder.ToTable(OAuthServerConstants.RequestTable);
        builder.HasKey(row => row.Id);
        builder.Property(row => row.Id).ValueGeneratedNever();
        builder.Property(row => row.ClientId).HasMaxLength(64);
        builder.Property(row => row.ClientName).HasMaxLength(200);
        builder.Property(row => row.RedirectUri).HasMaxLength(2048);
        builder.Property(row => row.RedirectHost).HasMaxLength(255);
        builder.Property(row => row.CodeChallenge).HasMaxLength(128);
        builder.Property(row => row.Scope).HasMaxLength(256);
        builder.Property(row => row.State).HasMaxLength(2048);
        builder.Property(row => row.Resource).HasMaxLength(2048);
        builder.HasIndex(row => row.UserId);
        builder.HasIndex(row => row.ExpiresAt);
    }
}
