using System.Reflection;
using AuthEndpoints.Jwt;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;

namespace AuthEndpoints.OpenIddict;

internal static class OAuthRequestLimits
{
    public const int NonceLength = 512;
    public const int AuthenticationMethodsLength = 128;
}

public static class OAuthServerModelBuilderExtensions
{
    /// <summary>
    /// Adds the OpenIddict entities, the <c>OAuthRequests</c> pending-consent table, and the <c>OAuthDeveloperApps</c>
    /// table, keyed by <typeparamref name="TUser"/>'s key type, with cascading foreign keys to <typeparamref name="TUser"/>.
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
        Configure(builder.Entity<OAuthDeveloperApp<TKey>>());
        if (userForeignKey)
        {
            builder.Entity<OAuthRequest<TKey>>()
                .HasOne<TUser>()
                .WithMany()
                .HasForeignKey(row => row.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Deleting the owner removes the row. The OpenIddict application is then refused at once
            // and deleted by the next cleanup pass.
            builder.Entity<OAuthDeveloperApp<TKey>>()
                .HasOne<TUser>()
                .WithMany()
                .HasForeignKey(row => row.OwnerId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }

    private static void Configure<TKey>(EntityTypeBuilder<OAuthDeveloperApp<TKey>> builder)
        where TKey : IEquatable<TKey>
    {
        builder.ToTable(OAuthServerConstants.DeveloperAppTable);
        builder.HasKey(row => row.Id);
        builder.Property(row => row.Id).ValueGeneratedNever();
        builder.Property(row => row.ClientId).HasMaxLength(64);
        builder.Property(row => row.Name).HasMaxLength(OAuthDeveloperAppLimits.NameLength);
        builder.Property(row => row.HomepageUrl).HasMaxLength(2048);
        builder.Property(row => row.Description).HasMaxLength(OAuthDeveloperAppLimits.DescriptionLength);
        builder.Property(row => row.Status).HasConversion<string>().HasMaxLength(32);
        builder.HasIndex(row => row.ClientId).IsUnique();
        builder.HasIndex(row => row.OwnerId);
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
        builder.Property(row => row.Nonce).HasMaxLength(OAuthRequestLimits.NonceLength);
        builder.Property(row => row.AuthenticationMethods).HasMaxLength(OAuthRequestLimits.AuthenticationMethodsLength);
        builder.HasIndex(row => row.UserId);
        builder.HasIndex(row => row.ExpiresAt);
    }
}
