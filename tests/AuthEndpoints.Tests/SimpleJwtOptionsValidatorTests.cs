using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Tests;

public class SimpleJwtOptionsValidatorTests
{
    private const string SigningKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";

    private const string RsaKeyMessage =
        "RsaKey is required when Algorithm is Rsa. Set SimpleJwtOptions.SigningOptions.RsaKey.";

    private const string CertificateMessage =
        "Certificate is required when Algorithm is X509. Set SimpleJwtOptions.SigningOptions.Certificate.";

    private const string EcdsaKeyMessage =
        "EcdsaKey is required when Algorithm is Ecdsa. Set SimpleJwtOptions.SigningOptions.EcdsaKey.";

    [Theory]
    [InlineData(null)]
    [InlineData(SecurityAlgorithms.RsaSha512)]
    public void Validate_RsaWithOnlyCertificate_FailsNamingRsaKey(string? algorithmOverride)
    {
        using var certificate = CreateCertificate();
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Rsa,
            AlgorithmOverride = algorithmOverride,
            Certificate = certificate,
        });

        Assert.Equal(RsaKeyMessage, result.FailureMessage);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(SecurityAlgorithms.RsaSha512)]
    public void Validate_X509WithOnlyRsaKey_FailsNamingCertificate(string? algorithmOverride)
    {
        using var rsa = RSA.Create(2048);
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.X509,
            AlgorithmOverride = algorithmOverride,
            RsaKey = rsa,
        });

        Assert.Equal(CertificateMessage, result.FailureMessage);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(SecurityAlgorithms.RsaSha512)]
    public void Validate_RsaWithRsaKey_Succeeds(string? algorithmOverride)
    {
        using var rsa = RSA.Create(2048);
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Rsa,
            AlgorithmOverride = algorithmOverride,
            RsaKey = rsa,
        });

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(SecurityAlgorithms.RsaSha512)]
    public void Validate_X509WithCertificate_Succeeds(string? algorithmOverride)
    {
        using var certificate = CreateCertificate();
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.X509,
            AlgorithmOverride = algorithmOverride,
            Certificate = certificate,
        });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_RsaWithRsaKeyAndCertificate_Succeeds()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateCertificate();
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Rsa,
            RsaKey = rsa,
            Certificate = certificate,
        });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_X509WithCertificateAndRsaKey_Succeeds()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateCertificate();
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.X509,
            RsaKey = rsa,
            Certificate = certificate,
        });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_EcdsaWithoutKey_FailsNamingEcdsaKey()
    {
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Ecdsa,
        });

        Assert.Equal(EcdsaKeyMessage, result.FailureMessage);
    }

    [Fact]
    public void Validate_EcdsaWithEcdsaKey_Succeeds()
    {
        using var ecdsa = ECDsa.Create();
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Ecdsa,
            EcdsaKey = ecdsa,
        });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_SymmetricWithKey_Succeeds()
    {
        var result = Validate(new SimpleJwtSigningOptions
        {
            Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Symmetric,
            SymmetricKey = SigningKey,
        });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void AddJwtEndpoints_RsaWithOnlyCertificate_FailsOptionsValidation()
    {
        using var certificate = CreateCertificate();
        var services = new ServiceCollection();

        var ex = Assert.Throws<OptionsValidationException>(() =>
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters();
                options.SigningOptions.Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Rsa;
                options.SigningOptions.Certificate = certificate;
            }));

        Assert.Equal(RsaKeyMessage, Assert.Single(ex.Failures));
    }

    [Fact]
    public void AddJwtEndpoints_X509WithOnlyRsaKey_FailsOptionsValidation()
    {
        using var rsa = RSA.Create(2048);
        var services = new ServiceCollection();

        var ex = Assert.Throws<OptionsValidationException>(() =>
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters();
                options.SigningOptions.Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.X509;
                options.SigningOptions.RsaKey = rsa;
            }));

        Assert.Equal(CertificateMessage, Assert.Single(ex.Failures));
    }

    [Fact]
    public void AddJwtEndpoints_RsaWithRsaKey_Succeeds()
    {
        using var rsa = RSA.Create(2048);
        var services = new ServiceCollection();

        var builder = services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
        {
            options.Issuer = "https://example.com";
            options.Audience = "https://example.com";
            options.SigningOptions.Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Rsa;
            options.SigningOptions.RsaKey = rsa;
        });

        Assert.NotNull(builder);
    }

    [Fact]
    public void AddJwtEndpoints_X509WithCertificate_Succeeds()
    {
        using var certificate = CreateCertificate();
        var services = new ServiceCollection();

        var builder = services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
        {
            options.Issuer = "https://example.com";
            options.Audience = "https://example.com";
            options.SigningOptions.Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.X509;
            options.SigningOptions.Certificate = certificate;
        });

        Assert.NotNull(builder);
    }

    [Fact]
    public async Task ValidateOnStart_RsaWithOnlyCertificate_FailsNamingRsaKey()
    {
        using var certificate = CreateCertificate();
        await using var app = BuildHost(signing =>
        {
            signing.Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Rsa;
            signing.Certificate = certificate;
            signing.RsaKey = null;
            signing.SymmetricKey = null;
        });

        await AssertStartupFailsAsync(app, RsaKeyMessage);
    }

    [Fact]
    public async Task ValidateOnStart_X509WithOnlyRsaKey_FailsNamingCertificate()
    {
        using var rsa = RSA.Create(2048);
        await using var app = BuildHost(signing =>
        {
            signing.Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.X509;
            signing.RsaKey = rsa;
            signing.Certificate = null;
            signing.SymmetricKey = null;
        });

        await AssertStartupFailsAsync(app, CertificateMessage);
    }

    [Fact]
    public async Task ValidateOnStart_RsaWithRsaKey_Starts()
    {
        using var rsa = RSA.Create(2048);
        await using var app = BuildHost(signing =>
        {
            signing.Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Rsa;
            signing.RsaKey = rsa;
            signing.SymmetricKey = null;
        });

        await app.StartAsync();
        var signing = app.Services.GetRequiredService<IOptions<SimpleJwtOptions>>().Value.SigningOptions;
        Assert.Equal(SimpleJwtSigningOptions.SigningAlgorithm.Rsa, signing.Algorithm);
        Assert.NotNull(signing.RsaKey);
        await app.StopAsync();
    }

    [Fact]
    public async Task ValidateOnStart_X509WithCertificate_Starts()
    {
        using var certificate = CreateCertificate();
        await using var app = BuildHost(signing =>
        {
            signing.Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.X509;
            signing.Certificate = certificate;
            signing.SymmetricKey = null;
        });

        await app.StartAsync();
        var signing = app.Services.GetRequiredService<IOptions<SimpleJwtOptions>>().Value.SigningOptions;
        Assert.Equal(SimpleJwtSigningOptions.SigningAlgorithm.X509, signing.Algorithm);
        Assert.NotNull(signing.Certificate);
        await app.StopAsync();
    }

    private static ValidateOptionsResult Validate(SimpleJwtSigningOptions signing)
    {
        var options = new SimpleJwtOptions
        {
            Issuer = "https://example.com",
            Audience = "https://example.com",
            SigningOptions = signing,
        };

        return new SimpleJwtOptionsValidator().Validate(nameof(SimpleJwtOptions), options);
    }

    private static WebApplication BuildHost(Action<SimpleJwtSigningOptions> configureSigning)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(options =>
            options.UseInMemoryDatabase("jwt-signing-" + Guid.NewGuid().ToString("N")));
        builder.Services
            .AddIdentityApiEndpoints<TestAppUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();
        SimpleJwtSigningOptions signing = null!;
        builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
        {
            options.Issuer = "https://example.com";
            options.Audience = "https://example.com";
            options.SigningOptions.SymmetricKey = SigningKey;
            signing = options.SigningOptions;
        });
        // AddJwtEndpoints already validated the symmetric snapshot. Mutating this instance
        // changes the options object signing reads and the options ValidateOnStart checks.
        configureSigning(signing);
        return builder.Build();
    }

    private static async Task AssertStartupFailsAsync(WebApplication app, string message)
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => app.StartAsync());
        var validation = ex as OptionsValidationException
            ?? ex.InnerException as OptionsValidationException;
        Assert.NotNull(validation);
        Assert.Equal(message, Assert.Single(validation.Failures));
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=authendpoints-jwt-test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var generated = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), password: null);
    }
}
