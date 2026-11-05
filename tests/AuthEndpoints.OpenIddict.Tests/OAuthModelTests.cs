using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>
/// Table, column, index, and constraint names are part of the package contract. Changing them
/// forces every adopting app into a data migration.
/// </summary>
public sealed class OAuthModelTests
{
    [Fact]
    public void Pending_consent_table_has_the_documented_schema()
    {
        using var db = new GuidDb();
        var entity = db.Model.FindEntityType(typeof(OAuthRequest<Guid>))!;
        var table = StoreObjectIdentifier.Table("OAuthRequests", null);

        Assert.Equal("OAuthRequests", entity.GetTableName());
        Assert.Equal("PK_OAuthRequests", entity.FindPrimaryKey()!.GetName());
        var expected = new Dictionary<string, (int? Length, bool Nullable)>
        {
            ["Id"] = (null, false),
            ["UserId"] = (null, false),
            ["ClientId"] = (64, false),
            ["ClientName"] = (200, false),
            ["RedirectUri"] = (2048, false),
            ["RedirectHost"] = (255, false),
            ["CodeChallenge"] = (128, false),
            ["Scope"] = (256, false),
            ["State"] = (2048, true),
            ["Resource"] = (2048, false),
            ["CreatedAt"] = (null, false),
            ["ExpiresAt"] = (null, false),
            ["ConsumedAt"] = (null, true),
        };
        Assert.Equal(expected.Keys.Order(), entity.GetProperties().Select(p => p.GetColumnName(table)!).Order());
        foreach (var property in entity.GetProperties())
        {
            var (length, nullable) = expected[property.GetColumnName(table)!];
            Assert.Equal(length, property.GetMaxLength());
            Assert.Equal(nullable, property.IsColumnNullable(table));
        }

        Assert.Equal(typeof(Guid), entity.FindProperty("Id")!.ClrType);
        Assert.Equal(typeof(Guid), entity.FindProperty("UserId")!.ClrType);
        Assert.Equal(ValueGenerated.Never, entity.FindProperty("Id")!.ValueGenerated);
        var foreignKey = Assert.Single(entity.GetForeignKeys());
        Assert.Equal("FK_OAuthRequests_AspNetUsers_UserId", foreignKey.GetConstraintName());
        Assert.Equal(DeleteBehavior.Cascade, foreignKey.DeleteBehavior);
        Assert.Equal(
            ["IX_OAuthRequests_ExpiresAt", "IX_OAuthRequests_UserId"],
            entity.GetIndexes().Select(index => index.GetDatabaseName()!).Order().ToArray());
    }

    [Fact]
    public void Developer_app_table_has_the_documented_schema()
    {
        using var db = new GuidDb();
        var entity = db.Model.FindEntityType(typeof(OAuthDeveloperApp<Guid>))!;
        var table = StoreObjectIdentifier.Table("OAuthDeveloperApps", null);

        Assert.Equal("OAuthDeveloperApps", entity.GetTableName());
        Assert.Equal("PK_OAuthDeveloperApps", entity.FindPrimaryKey()!.GetName());
        var expected = new Dictionary<string, (int? Length, bool Nullable)>
        {
            ["Id"] = (null, false),
            ["OwnerId"] = (null, false),
            ["ClientId"] = (64, false),
            ["Name"] = (200, false),
            ["HomepageUrl"] = (2048, false),
            ["Description"] = (1000, true),
            ["Confidential"] = (null, false),
            ["Status"] = (32, false),
            ["CreatedAt"] = (null, false),
            ["UpdatedAt"] = (null, false),
            ["SecretCreatedAt"] = (null, true),
        };
        Assert.Equal(expected.Keys.Order(), entity.GetProperties().Select(p => p.GetColumnName(table)!).Order());
        foreach (var property in entity.GetProperties())
        {
            var (length, nullable) = expected[property.GetColumnName(table)!];
            Assert.Equal(length, property.GetMaxLength());
            Assert.Equal(nullable, property.IsColumnNullable(table));
        }

        Assert.Equal(typeof(string), entity.FindProperty("Status")!.GetProviderClrType());
        Assert.Equal(ValueGenerated.Never, entity.FindProperty("Id")!.ValueGenerated);
        var foreignKey = Assert.Single(entity.GetForeignKeys());
        Assert.Equal("FK_OAuthDeveloperApps_AspNetUsers_OwnerId", foreignKey.GetConstraintName());
        Assert.Equal(DeleteBehavior.Cascade, foreignKey.DeleteBehavior);
        Assert.Equal(
            ["IX_OAuthDeveloperApps_ClientId", "IX_OAuthDeveloperApps_OwnerId"],
            entity.GetIndexes().Select(index => index.GetDatabaseName()!).Order().ToArray());
        Assert.True(entity.GetIndexes().Single(index => index.GetDatabaseName() == "IX_OAuthDeveloperApps_ClientId").IsUnique);
    }

    [Fact]
    public void OpenIddict_tables_have_the_documented_schema()
    {
        using var db = new GuidDb();
        Assert.Equal("OpenIddictApplications", db.Model.FindEntityType(typeof(OpenIddictEntityFrameworkCoreApplication))!.GetTableName());
        Assert.Equal("OpenIddictAuthorizations", db.Model.FindEntityType(typeof(OpenIddictEntityFrameworkCoreAuthorization))!.GetTableName());
        Assert.Equal("OpenIddictScopes", db.Model.FindEntityType(typeof(OpenIddictEntityFrameworkCoreScope))!.GetTableName());
        var tokens = db.Model.FindEntityType(typeof(OpenIddictEntityFrameworkCoreToken))!;
        Assert.Equal("OpenIddictTokens", tokens.GetTableName());
        Assert.Equal(512, tokens.FindProperty(nameof(OpenIddictEntityFrameworkCoreToken.ReferenceId))!.GetMaxLength());
        Assert.Contains(tokens.GetIndexes(), index => index.GetDatabaseName() == "IX_OpenIddictTokens_ReferenceId");
    }

    [Fact]
    public void The_key_type_comes_from_the_user_type()
    {
        using var guid = new GuidDb();
        Assert.Equal(typeof(Guid), guid.Model.FindEntityType(typeof(OAuthRequest<Guid>))!.FindProperty("UserId")!.ClrType);
        Assert.Null(guid.Model.FindEntityType(typeof(OAuthRequest<string>)));
    }

    [Fact]
    public void A_user_type_that_is_not_an_IdentityUser_is_rejected()
    {
        var model = new ModelBuilder();
        Assert.Throws<InvalidOperationException>(() => model.UseAuthEndpointsOpenIddict<NotAUser>());
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddAuthEndpointsOpenIddict<NotAUser, NoUserDb>());
    }

    [Fact]
    public void Without_the_user_foreign_key_there_is_no_foreign_key()
    {
        using var db = new NoUserDb();
        Assert.Empty(db.Model.FindEntityType(typeof(OAuthRequest<string>))!.GetForeignKeys());
        Assert.Empty(db.Model.FindEntityType(typeof(OAuthDeveloperApp<string>))!.GetForeignKeys());
    }

    private sealed class NotAUser;

    private sealed class GuidDb : IdentityDbContext<IdentityUser<Guid>, IdentityRole<Guid>, Guid>
    {
        protected override void OnConfiguring(DbContextOptionsBuilder options) => options.UseSqlite("Data Source=:memory:");

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.UseAuthEndpointsOpenIddict<IdentityUser<Guid>>();
        }
    }

    private sealed class NoUserDb : DbContext
    {
        protected override void OnConfiguring(DbContextOptionsBuilder options) => options.UseSqlite("Data Source=:memory:");

        protected override void OnModelCreating(ModelBuilder builder) => builder.UseAuthEndpointsOpenIddict<IdentityUser>(userForeignKey: false);
    }
}

public sealed class OAuthOptionsTests
{
    [Fact]
    public void Defaults_are_the_safe_ones()
    {
        var options = new OAuthServerOptions();
        Assert.False(options.DisableTransportSecurityRequirement);
        Assert.False(options.DisableResourceValidation);
        Assert.False(options.IgnoreResourcePermissions);
        Assert.False(options.DynamicRegistration.Enabled);
        Assert.False(options.ProtectedResource.Enabled);
        Assert.False(options.DeveloperApps.RequireApproval);
        Assert.Equal(10, options.DeveloperApps.MaxAppsPerUser);
        Assert.False(options.Certificates.UseEphemeralKeys);
        Assert.Equal(TimeSpan.FromMinutes(15), options.AccessTokenLifetime);
        Assert.Equal(TimeSpan.FromMinutes(5), options.AuthorizationCodeLifetime);
        Assert.Equal(IdentityConstants.ApplicationScheme, options.AuthenticationScheme);
    }

    [Fact]
    public void Missing_settings_fail_validation()
    {
        var result = new OAuthServerOptionsValidator().Validate(null, new OAuthServerOptions());

        Assert.True(result.Failed);
        var message = string.Join('\n', result.Failures!);
        Assert.Contains("Issuer", message, StringComparison.Ordinal);
        Assert.Contains("Audience is required", message, StringComparison.Ordinal);
        Assert.Contains("LoginUrl", message, StringComparison.Ordinal);
        Assert.Contains("ConsentUrl", message, StringComparison.Ordinal);
        Assert.Contains("Certificates", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Http_issuer_needs_the_explicit_opt_out()
    {
        var options = Valid();
        options.Issuer = new Uri("http://localhost:5000/");
        Assert.True(new OAuthServerOptionsValidator().Validate(null, options).Failed);

        options.DisableTransportSecurityRequirement = true;
        Assert.True(new OAuthServerOptionsValidator().Validate(null, options).Succeeded);
    }

    [Theory]
    [InlineData("//evil.example/login")]
    [InlineData("/\\evil.example")]
    [InlineData("javascript:alert(1)")]
    [InlineData("relative/login")]
    public void Login_and_consent_urls_must_be_absolute_http_or_rooted(string url)
    {
        var options = Valid();
        options.LoginUrl = url;
        Assert.True(new OAuthServerOptionsValidator().Validate(null, options).Failed);
    }

    [Fact]
    public void Default_scopes_and_client_settings_are_checked()
    {
        var options = Valid();
        options.DefaultScopes.Add("missing");
        options.Clients.Add(new OAuthClientDefinition { ClientId = "c" });
        var failures = string.Join('\n', new OAuthServerOptionsValidator().Validate(null, options).Failures!);
        Assert.Contains("Default scope 'missing'", failures, StringComparison.Ordinal);
        Assert.Contains("needs at least one redirect URI", failures, StringComparison.Ordinal);
    }

    [Fact]
    public void Only_one_certificate_source_is_allowed()
    {
        var options = Valid();
        options.Certificates.Path = "/tmp/keys";
        Assert.True(new OAuthServerOptionsValidator().Validate(null, options).Failed);
    }

    [Fact]
    public async Task An_invalid_configuration_stops_startup()
    {
        await Assert.ThrowsAsync<OptionsValidationException>(() => OAuthTestHost.StartAsync(options => options.Audience = null));
    }

    [Fact]
    public void Persisted_certificates_are_reused_across_restarts()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ae-oauth-keys-{Guid.NewGuid():N}");
        try
        {
            string Thumbprint()
            {
                var services = new ServiceCollection();
                services.AddDbContext<NoopDb>();
                services.AddDbContext<IdentityDbContext>(o => o.UseSqlite("Data Source=:memory:"));
                services.AddIdentityCore<IdentityUser>().AddEntityFrameworkStores<IdentityDbContext>();
                services.AddAuthEndpointsOpenIddict<IdentityUser, NoopDb>(options =>
                {
                    options.Issuer = new Uri("https://localhost/");
                    options.Audience = "https://localhost/api";
                    options.LoginUrl = "/login";
                    options.ConsentUrl = "/consent";
                    options.Certificates.Path = path;
                });
                using var provider = services.BuildServiceProvider();
                var server = provider.GetRequiredService<IOptions<global::OpenIddict.Server.OpenIddictServerOptions>>().Value;
                return server.SigningCredentials.Select(c => c.Key.KeyId).First(id => id is not null)!;
            }

            Assert.Equal(Thumbprint(), Thumbprint());
            Assert.True(File.Exists(Path.Combine(path, "oauth-signing.pfx")));
            Assert.True(File.Exists(Path.Combine(path, "oauth-encryption.pfx")));
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(path, "oauth-cert-password")));
            }
        }
        finally
        {
            Directory.Delete(path, recursive: true);
        }
    }

    private static OAuthServerOptions Valid()
    {
        var options = new OAuthServerOptions
        {
            Issuer = new Uri("https://localhost/"),
            Audience = "https://localhost/api",
            LoginUrl = "https://app.example/login",
            ConsentUrl = "/consent",
        };
        options.Certificates.UseEphemeralKeys = true;
        return options;
    }

    private sealed class NoopDb : DbContext
    {
        protected override void OnConfiguring(DbContextOptionsBuilder options) => options.UseSqlite("Data Source=:memory:");

        protected override void OnModelCreating(ModelBuilder builder) => builder.UseAuthEndpointsOpenIddict<IdentityUser>(userForeignKey: false);
    }
}
