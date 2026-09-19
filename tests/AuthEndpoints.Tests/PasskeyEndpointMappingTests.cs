using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

public class PasskeyEndpointMappingTests
{
    [Fact]
    public void MapPasskeyEndpoints_WithPasskeyAndEmailSupport_DoesNotThrow()
    {
        using var app = CreateApp();

        var mapped = app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>();

        Assert.NotNull(mapped);
    }

    [Fact]
    public void MapPasskeyEndpoints_WithoutPasskeySupport_ThrowsNotSupported()
    {
        using var app = CreateApp(services =>
        {
            services.Replace(ServiceDescriptor.Scoped<UserManager<TestAppUser>, UserManagerWithoutPasskeys>());
        });

        var ex = Assert.Throws<NotSupportedException>(
            () => app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>());

        Assert.Contains("passkey support", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(nameof(PasskeyApiEndpointRouteBuilderExtensions.MapPasskeyEndpoints), ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MapPasskeyEndpoints_WithoutEmailSupport_ThrowsNotSupported()
    {
        using var app = CreateApp(services =>
        {
            services.Replace(ServiceDescriptor.Scoped<UserManager<TestAppUser>, UserManagerWithoutEmail>());
        });

        var ex = Assert.Throws<NotSupportedException>(
            () => app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>());

        Assert.Contains("email support", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(nameof(PasskeyApiEndpointRouteBuilderExtensions.MapPasskeyEndpoints), ex.Message, StringComparison.Ordinal);
    }

    private static WebApplication CreateApp(Action<IServiceCollection>? configureServices = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("PasskeyMap_" + Guid.NewGuid().ToString("N")));
        builder.Services
            .AddIdentityApiEndpoints<TestAppUser>(options =>
            {
                options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        configureServices?.Invoke(builder.Services);

        return builder.Build();
    }

    private sealed class UserManagerWithoutPasskeys(
        IUserStore<TestAppUser> store,
        IOptions<IdentityOptions> optionsAccessor,
        IPasswordHasher<TestAppUser> passwordHasher,
        IEnumerable<IUserValidator<TestAppUser>> userValidators,
        IEnumerable<IPasswordValidator<TestAppUser>> passwordValidators,
        ILookupNormalizer keyNormalizer,
        IdentityErrorDescriber errors,
        IServiceProvider services,
        ILogger<UserManager<TestAppUser>> logger)
        : UserManager<TestAppUser>(
            store,
            optionsAccessor,
            passwordHasher,
            userValidators,
            passwordValidators,
            keyNormalizer,
            errors,
            services,
            logger)
    {
        public override bool SupportsUserPasskey => false;
    }

    private sealed class UserManagerWithoutEmail(
        IUserStore<TestAppUser> store,
        IOptions<IdentityOptions> optionsAccessor,
        IPasswordHasher<TestAppUser> passwordHasher,
        IEnumerable<IUserValidator<TestAppUser>> userValidators,
        IEnumerable<IPasswordValidator<TestAppUser>> passwordValidators,
        ILookupNormalizer keyNormalizer,
        IdentityErrorDescriber errors,
        IServiceProvider services,
        ILogger<UserManager<TestAppUser>> logger)
        : UserManager<TestAppUser>(
            store,
            optionsAccessor,
            passwordHasher,
            userValidators,
            passwordValidators,
            keyNormalizer,
            errors,
            services,
            logger)
    {
        public override bool SupportsUserEmail => false;
    }
}
