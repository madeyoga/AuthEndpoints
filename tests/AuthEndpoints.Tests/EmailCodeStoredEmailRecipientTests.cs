using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

public partial class EmailCodeEndpointTests
{
    [Fact]
    public async Task ForgotPassword_SendsToStoredEmail()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var stored = UniqueEmail("stored").ToLowerInvariant();
        await SeedAsync(host.App, stored);
        var variant = stored.ToUpperInvariant();
        Assert.NotEqual(stored, variant);

        var response = await PostAsync(host.Client, "/identity/forgotPassword", new { email = variant });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var mail = Assert.Single(host.Mail.Snapshot(), item => item.Kind == "reset");
        Assert.Equal(stored, mail.Email);
    }

    [Fact]
    public async Task ForgotPassword_SameEmailString_SendsToStoredEmail()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var stored = UniqueEmail("same").ToLowerInvariant();
        await SeedAsync(host.App, stored);

        var response = await PostAsync(host.Client, "/identity/forgotPassword", new { email = stored });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(stored, Assert.Single(host.Mail.Snapshot(), item => item.Kind == "reset").Email);
    }

    [Fact]
    public async Task ForgotPassword_EmptyStoredEmail_SendsNothingAndReturnsOk()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var stored = UniqueEmail("empty").ToLowerInvariant();
        await SeedAsync(host.App, stored);
        await ClearStoredEmailAsync(host.App, stored);

        var response = await PostAsync(host.Client, "/identity/forgotPassword", new { email = stored });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain(host.Mail.Snapshot(), item => item.Kind == "reset");
    }

    [Fact]
    public async Task EmailCodeSend_SendsToStoredEmail()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var stored = UniqueEmail("stored").ToLowerInvariant();
        await SeedAsync(host.App, stored);
        var variant = stored.ToUpperInvariant();
        Assert.NotEqual(stored, variant);

        var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email = variant });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var mail = Assert.Single(host.Mail.Snapshot(), item => item.Kind == "email-code");
        Assert.Equal(stored, mail.Email);

        // The row is keyed by the normalized address, so verifying with either spelling still works.
        var verify = await PostAsync(host.Client, "/identity/emailCode/verify?useCookies=true", new { email = variant, code = mail.Body });
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
    }

    [Fact]
    public async Task EmailCodeSend_SameEmailString_SendsToStoredEmail()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var stored = UniqueEmail("same").ToLowerInvariant();
        await SeedAsync(host.App, stored);

        var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email = stored });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(stored, Assert.Single(host.Mail.Snapshot(), item => item.Kind == "email-code").Email);
    }

    [Fact]
    public async Task EmailCodeSend_EmptyStoredEmail_SendsNothingAndReturnsOk()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var stored = UniqueEmail("empty").ToLowerInvariant();
        await SeedAsync(host.App, stored);
        await ClearStoredEmailAsync(host.App, stored);

        var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email = stored });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain(host.Mail.Snapshot(), item => item.Kind == "email-code");
        Assert.Null((await RowsAsync(host.App, stored)).Single().UserId);
    }

    [Fact]
    public async Task EmailCodeSend_UnknownAddressWithSignUp_SendsToRequestEmail()
    {
        await using var host = await EmailCodeHost.StartAsync(options => options.AllowSignUp = true);
        var requested = UniqueEmail("new").ToLowerInvariant();

        var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email = requested });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(requested, Assert.Single(host.Mail.Snapshot(), item => item.Kind == "email-code").Email);
    }

    private static async Task ClearStoredEmailAsync(Microsoft.AspNetCore.Builder.WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        var rows = await db.Database.ExecuteSqlRawAsync(
            "UPDATE AspNetUsers SET Email = '' WHERE NormalizedEmail = {0}",
            email.ToUpperInvariant());
        Assert.Equal(1, rows);
    }
}
