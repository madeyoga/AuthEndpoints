using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

internal static class TestHelpers
{
    public const string DefaultPassword = "Passw0rd!";

    public static async Task<TestAppUser> SeedUserAsync(
        TestWebApplicationFactory factory,
        string email = "user@test.local",
        string password = DefaultPassword,
        bool twoFactorEnabled = false)
    {
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();

        var existing = await userManager.FindByEmailAsync(email);
        if (existing is not null)
        {
            await userManager.DeleteAsync(existing);
        }

        var user = new TestAppUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true
        };

        var create = await userManager.CreateAsync(user, password);
        Assert.True(create.Succeeded, string.Join("; ", create.Errors.Select(e => e.Description)));

        if (twoFactorEnabled)
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            var enable = await userManager.SetTwoFactorEnabledAsync(user, true);
            Assert.True(enable.Succeeded, string.Join("; ", enable.Errors.Select(e => e.Description)));
        }

        return user;
    }

    public static HttpClient CreateClientWithCookies(TestWebApplicationFactory factory)
    {
        return factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });
    }

    public static async Task<string> GetCsrfTokenAsync(HttpClient client)
    {
        var response = await client.GetAsync("/identity/csrfToken");
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (doc.RootElement.TryGetProperty("csrfToken", out var camel))
        {
            return camel.GetString()!;
        }

        return doc.RootElement.GetProperty("CsrfToken").GetString()!;
    }

    public static async Task LoginCookieAsync(HttpClient client, string email, string password)
    {
        var response = await client.PostAsJsonAsync(
            "/identity/login",
            new { email, password });
        Assert.True(
            response.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"Login failed: {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    public static async Task<string> CreateJwtAsync(HttpClient client, string email, string password)
    {
        var response = await client.PostAsJsonAsync("/auth/create", new { email, password });
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (doc.RootElement.TryGetProperty("accessToken", out var camel))
        {
            return camel.GetString()!;
        }

        return doc.RootElement.GetProperty("AccessToken").GetString()!;
    }

    public static void SetBearer(HttpClient client, string accessToken)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    }
}
