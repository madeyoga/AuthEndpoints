using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthEndpoints.EmailCode;

public class EmailCodeConfiguration : IEntityTypeConfiguration<EmailCode>
{
    public void Configure(EntityTypeBuilder<EmailCode> builder)
    {
        builder.ToTable("AuthEndpointsEmailCodes", "AuthEndpoints");
        builder.HasKey(e => e.Id);
        builder.Property(e => e.EmailHash).IsRequired();
        builder.Property(e => e.CodeHash).IsRequired();
        builder.HasIndex(e => new { e.EmailHash, e.CreatedAt });
        builder.HasIndex(e => e.LinkTokenHash)
            .IsUnique()
            .HasFilter("\"LinkTokenHash\" IS NOT NULL");
    }
}

public static class EntityFrameworkCoreHelpers
{
    /// <summary>
    /// Maps the email-code entity (<c>AuthEndpoints.AuthEndpointsEmailCodes</c>).
    /// Call from <c>DbContext.OnModelCreating</c> when email-code sign-in is enabled.
    /// The table is not created unless this method is called.
    /// </summary>
    public static ModelBuilder UseEmailCodes(this ModelBuilder builder)
    {
        builder.ApplyConfiguration(new EmailCodeConfiguration());
        return builder;
    }
}
