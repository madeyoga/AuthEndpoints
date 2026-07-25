using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

internal static class TestHelpers
{
    public const string DefaultPassword = "Passw0rd!";

    public static async Task<TestAppUser> SeedUserAsync(
        TestWebApplicationFactory factory,
        string email = "user@test.local",
        string password = DefaultPassword,
        bool twoFactorEnabled = false,
        bool emailConfirmed = true)
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
            EmailConfirmed = emailConfirmed
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

    public static async Task<string> GetCsrfTokenAsync(HttpClient client, string path = "/identity/csrfToken")
    {
        var response = await client.GetAsync(path);
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

    public static async Task<HttpResponseMessage> PostWithCsrfAsync(
        HttpClient client,
        string url,
        object? body,
        string? reauthToken = null,
        string csrfPath = "/identity/csrfToken")
    {
        for (var attempt = 0; attempt < 6; attempt++)
        {
            var csrf = await GetCsrfTokenAsync(client, csrfPath);
            using var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = body is null ? null : JsonContent.Create(body)
            };
            request.Headers.Add("RequestVerificationToken", csrf);
            if (!string.IsNullOrEmpty(reauthToken))
            {
                request.Headers.Add(AuthEndpointsConstants.ReAuthHeaderName, reauthToken);
            }

            var response = await client.SendAsync(request);
            if (response.StatusCode != HttpStatusCode.TooManyRequests)
            {
                return response;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        var csrfFinal = await GetCsrfTokenAsync(client, csrfPath);
        using var finalRequest = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = body is null ? null : JsonContent.Create(body)
        };
        finalRequest.Headers.Add("RequestVerificationToken", csrfFinal);
        if (!string.IsNullOrEmpty(reauthToken))
        {
            finalRequest.Headers.Add(AuthEndpointsConstants.ReAuthHeaderName, reauthToken);
        }

        return await client.SendAsync(finalRequest);
    }

    public static async Task<string> ConfirmIdentityAsync(
        HttpClient client,
        object proof,
        bool useCsrf = true)
    {
        HttpResponseMessage response;
        if (useCsrf)
        {
            response = await PostWithCsrfAsync(client, "/identity/confirmIdentity", proof);
        }
        else
        {
            response = await client.PostAsJsonAsync("/identity/confirmIdentity", proof);
        }

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var token = TryGetString(doc.RootElement, "reauthToken", "ReauthToken");
        Assert.False(string.IsNullOrWhiteSpace(token), "Expected reauthToken in ConfirmIdentity response.");
        return token!;
    }

    public static async Task<string> ConfirmIdentityBearerAsync(HttpClient client, object proof)
    {
        var response = await client.PostAsJsonAsync("/identity/bearer/confirmIdentity", proof);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var token = TryGetString(doc.RootElement, "reauthToken", "ReauthToken");
        Assert.False(string.IsNullOrWhiteSpace(token), "Expected reauthToken in ConfirmIdentity response.");
        return token!;
    }

    public static void SetReauthToken(HttpClient client, string reauthToken)
    {
        client.DefaultRequestHeaders.Remove(AuthEndpointsConstants.ReAuthHeaderName);
        client.DefaultRequestHeaders.Add(AuthEndpointsConstants.ReAuthHeaderName, reauthToken);
    }

    public static async Task<(string AccessToken, string RefreshToken)> LoginBearerAsync(
        HttpClient client,
        string email,
        string password,
        string? twoFactorCode = null,
        string? twoFactorRecoveryCode = null)
    {
        var response = await client.PostAsJsonAsync(
            "/identity/bearer/login",
            new
            {
                email,
                password,
                twoFactorCode,
                twoFactorRecoveryCode
            });
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (ReadToken(doc.RootElement, "accessToken", "AccessToken"),
            ReadToken(doc.RootElement, "refreshToken", "RefreshToken"));
    }

    public static async Task<string> CreateJwtAsync(HttpClient client, string email, string password)
    {
        HttpResponseMessage? response = null;
        for (var attempt = 0; attempt < 6; attempt++)
        {
            response = await client.PostAsJsonAsync("/auth/create", new { email, password });
            if (response.StatusCode != HttpStatusCode.TooManyRequests)
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        response!.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return ReadToken(doc.RootElement, "accessToken", "AccessToken");
    }

    public static void SetBearer(HttpClient client, string accessToken)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    }

    public static async Task<string> GenerateEmailConfirmationCodeAsync(
        TestWebApplicationFactory factory,
        TestAppUser user)
    {
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var tracked = await userManager.FindByIdAsync(user.Id)
            ?? throw new InvalidOperationException($"User {user.Id} not found.");
        var code = await userManager.GenerateEmailConfirmationTokenAsync(tracked);
        return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
    }

    public static async Task<string> GeneratePasswordResetCodeAsync(
        TestWebApplicationFactory factory,
        TestAppUser user)
    {
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var tracked = await userManager.FindByIdAsync(user.Id)
            ?? throw new InvalidOperationException($"User {user.Id} not found.");
        var code = await userManager.GeneratePasswordResetTokenAsync(tracked);
        return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
    }

    public static async Task EnsureAuthenticatorKeyAsync(
        TestWebApplicationFactory factory,
        TestAppUser user)
    {
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var tracked = await userManager.FindByIdAsync(user.Id)
            ?? throw new InvalidOperationException($"User {user.Id} not found.");
        var key = await userManager.GetAuthenticatorKeyAsync(tracked);
        if (string.IsNullOrEmpty(key))
        {
            await userManager.ResetAuthenticatorKeyAsync(tracked);
        }
    }

    public static async Task<string> GetAuthenticatorKeyAsync(
        TestWebApplicationFactory factory,
        TestAppUser user)
    {
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var tracked = await userManager.FindByIdAsync(user.Id)
            ?? throw new InvalidOperationException($"User {user.Id} not found.");

        var key = await userManager.GetAuthenticatorKeyAsync(tracked);
        if (string.IsNullOrEmpty(key))
        {
            await userManager.ResetAuthenticatorKeyAsync(tracked);
            key = await userManager.GetAuthenticatorKeyAsync(tracked);
        }

        Assert.False(string.IsNullOrEmpty(key), "Expected an authenticator shared key.");
        return key!;
    }

    public static async Task<string> GenerateAuthenticatorCodeAsync(
        TestWebApplicationFactory factory,
        TestAppUser user)
    {
        var key = await GetAuthenticatorKeyAsync(factory, user);
        return TotpHelper.GenerateCode(key);
    }

    public static async Task<string[]> GenerateRecoveryCodesAsync(
        TestWebApplicationFactory factory,
        TestAppUser user,
        int count = 10)
    {
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var tracked = await userManager.FindByIdAsync(user.Id)
            ?? throw new InvalidOperationException($"User {user.Id} not found.");
        var codes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(tracked, count);
        Assert.NotNull(codes);
        return codes.ToArray();
    }

    public static async Task<TestAppUser?> FindUserByEmailAsync(
        TestWebApplicationFactory factory,
        string email)
    {
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        return await userManager.FindByEmailAsync(email);
    }

    public static bool TryGetBool(JsonElement root, string camel, string pascal, out bool value)
    {
        if (root.TryGetProperty(camel, out var camelProp))
        {
            value = camelProp.GetBoolean();
            return true;
        }

        if (root.TryGetProperty(pascal, out var pascalProp))
        {
            value = pascalProp.GetBoolean();
            return true;
        }

        value = false;
        return false;
    }

    public static string? TryGetString(JsonElement root, string camel, string pascal)
    {
        if (root.TryGetProperty(camel, out var camelProp))
        {
            return camelProp.GetString();
        }

        if (root.TryGetProperty(pascal, out var pascalProp))
        {
            return pascalProp.GetString();
        }

        return null;
    }

    private static string ReadToken(JsonElement root, string camel, string pascal)
    {
        var token = TryGetString(root, camel, pascal);
        Assert.False(string.IsNullOrWhiteSpace(token), $"Missing token property {camel}/{pascal}.");
        return token!;
    }
}
