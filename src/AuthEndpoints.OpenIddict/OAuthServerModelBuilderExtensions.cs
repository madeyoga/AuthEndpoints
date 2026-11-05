using System.Reflection;
using AuthEndpoints.Jwt;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;

namespace AuthEndpoints.OpenIddict;

public static class OAuthServerModelBuilderExtensions
{
    /// <summary>
    /// Adds the OpenIddict entities and the <c>OAuthRequests</c> pending-consent table, keyed by
    /// <typeparamref name="TUser"/>'s key type, with a cascading foreign key to <typeparamref name="TUser"/>.
    /// Call it from <c>OnModelCreating</c> after <c>base.OnModelCreating</c>, then add a migration.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type. It must derive from <c>IdentityUser&lt;TKey&gt;</c>.</typeparam>
    /// <param name="builder">The model builder.</param>
    /// <param name="userForeignKey">
    /// <see langword="false"/> when the users table is not in this context, for example when Identity uses a separate DbContext.
    /// </param>
    public static ModelBuilder UseAuthEndpointsOpenIddict<TUser>(this ModelBuilder builder, bool userForeignKey = true)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        var keyType = TypeHelper.FindKeyType(typeof(TUser));
        typeof(OAuthServerModelBuilderExtensions)
            .GetMethod(nameof(Apply), BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(typeof(TUser), keyType)
            .Invoke(null, BindingFlags.DoNotWrapExceptions, binder: null, [builder, userForeignKey], culture: null);
        return builder;
    }

    private static void Apply<TUser, TKey>(ModelBuilder builder, bool userForeignKey)
        where TUser : class
        where TKey : IEquatable<TKey>
    {
        builder.UseOpenIddict();
        builder.Entity<OpenIddictEntityFrameworkCoreToken>()
            .Property(token => token.ReferenceId)
            .HasMaxLength(OAuthServerConstants.ReferenceTokenLength);
        Configure(builder.Entity<OAuthRequest<TKey>>());
        if (userForeignKey)
        {
            builder.Entity<OAuthRequest<TKey>>()
                .HasOne<TUser>()
                .WithMany()
                .HasForeignKey(row => row.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
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
