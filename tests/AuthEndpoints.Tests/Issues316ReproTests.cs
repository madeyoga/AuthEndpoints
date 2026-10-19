using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.Tests;

/// <summary>
/// Issue 316: https://github.com/madeyoga/AuthEndpoints/issues/316
/// An extra cookie or identity-management map on the password facade throws the missing-Add guard.
/// </summary>
public sealed class Issues316ReproTests
{
    private const string SigningKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";

    private static void ExtraMap_ThrowsMissingAdd(string? serverDomain)
    {
        using var app = Build(serverDomain);
        app.MapPasswordAuth<TestAppUser>();

        var cookie = Assert.Throws<InvalidOperationException>(() =>
            app.MapGroup("/auth").MapCookieAuthEndpoints<TestAppUser>());
        Assert.Equal("Call AddPasswordEndpoints before MapCookieAuthEndpoints.", cookie.Message);

        var management = Assert.Throws<InvalidOperationException>(() =>
            app.MapGroup("/auth").MapIdentityManagementApi<TestAppUser>());
        Assert.Equal("Call AddPasswordEndpoints before MapPasswordEndpoints.", management.Message);
    }

    [Fact]
    public void Issue316_WithServerDomain_ExtraMapsThrowMissingAdd()
    {
        ExtraMap_ThrowsMissingAdd("localhost");
    }

    [Fact]
    public void Issue316_WithoutServerDomain_ExtraMapsThrowMissingAdd()
    {
        ExtraMap_ThrowsMissingAdd(null);
    }

    private static WebApplication Build(string? serverDomain)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.Services.AddDbContext<TestDbContext>(options =>
            options.UseInMemoryDatabase("issue-316-" + Guid.NewGuid().ToString("N")));
        builder.Services.AddSingleton<IEmailSender<TestAppUser>, TestEmailSender>();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(options =>
        {
            options.Session = AuthEndpointsSession.Jwt;
            options.Passkeys.ServerDomain = serverDomain;
            options.Jwt = jwt =>
            {
                jwt.SigningOptions.SymmetricKey = SigningKey;
                jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
            };
        });
        return builder.Build();
    }
}
