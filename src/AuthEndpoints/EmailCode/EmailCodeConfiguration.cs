using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthEndpoints.EmailCode;

public class EmailCodeConfiguration : IEntityTypeConfiguration<EmailCodeEntry>
{
    public void Configure(EntityTypeBuilder<EmailCodeEntry> builder)
    {
        builder.ToTable("AuthEndpointsEmailCodes", "AuthEndpoints");
        builder.HasKey(e => e.Id);
        builder.Property(e => e.EmailHash).IsRequired();
        builder.Property(e => e.CodeHash).IsRequired();
        builder.Property(e => e.Purpose)
            .HasDefaultValue(EmailCodeRowPurpose.SignIn)
            .HasSentinel((EmailCodeRowPurpose)(-1));
        builder.HasIndex(e => new { e.EmailHash, e.Purpose, e.CreatedAt })
            .HasDatabaseName("IX_AuthEndpointsEmailCodes_EmailHash_Purpose_CreatedAt");
        builder.HasIndex(e => e.LinkTokenHash).IsUnique();
    }
}

public static class EmailCodeModelBuilderExtensions
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
