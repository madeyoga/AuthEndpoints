using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.Passkey;

namespace AuthEndpoints.Tests;

public class PasskeyManagementSecurityTests
{
    public static TheoryData<string> SignInModes => new()
    {
        "cookie",
        "identity-bearer",
        "jwt"
    };

    [Theory]
    [MemberData(nameof(SignInModes))]
    public async Task ListAddRenameDelete_RequirePrimarySignIn_AndReauthOnMutations(string mode)
    {
        using var factory = new TestWebApplicationFactory();
        var email = $"pk-auth-{mode}-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var anonymous = factory.CreateClient();
        var anonymousList = await anonymous.GetAsync("/account/passkeys/");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousList.StatusCode);

        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var csrfOnMutations = mode == "cookie";
        await SignInAsync(client, mode, email);

        var list = await client.GetAsync("/account/passkeys/");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        Assert.Empty(await ReadPasskeysAsync(list));

        var beforeReauth = await SendAsync(
            client,
            HttpMethod.Post,
            "/account/passkeys/creationOptions",
            new { },
            csrf: true,
            reauth: null);
        Assert.Equal(HttpStatusCode.Forbidden, beforeReauth.StatusCode);

        var reauth = await ConfirmAsync(client, csrfOnMutations);

        if (csrfOnMutations)
        {
            var missingCsrf = await SendAsync(
                client,
                HttpMethod.Post,
                "/account/passkeys/creationOptions",
                new { },
                csrf: false,
                reauth);
            Assert.Equal(HttpStatusCode.BadRequest, missingCsrf.StatusCode);
            Assert.Contains("CSRF", await missingCsrf.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        }

        var options = await SendAsync(
            client,
            HttpMethod.Post,
            "/account/passkeys/creationOptions",
            new { },
            csrfOnMutations,
            reauth);
        var optionsBody = await options.Content.ReadAsStringAsync();
        Assert.True(options.StatusCode == HttpStatusCode.OK, optionsBody);
        var credentialJson = authenticator.CreateAttestation(optionsBody, origin);

        if (csrfOnMutations)
        {
            var addMissingCsrf = await SendAsync(
                client,
                HttpMethod.Post,
                "/account/passkeys/",
                new { credentialJson, name = "Laptop" },
                csrf: false,
                reauth);
            Assert.Equal(HttpStatusCode.BadRequest, addMissingCsrf.StatusCode);
        }

        var add = await SendAsync(
            client,
            HttpMethod.Post,
            "/account/passkeys/",
            new { credentialJson, name = "  Laptop  " },
            csrfOnMutations,
            reauth);
        var addBody = await add.Content.ReadAsStringAsync();
        Assert.True(add.StatusCode == HttpStatusCode.OK, addBody);
        using var addDoc = JsonDocument.Parse(addBody);
        Assert.Equal("Laptop", TestHelpers.TryGetString(addDoc.RootElement, "displayName", "DisplayName"));
        var credentialId = TestHelpers.TryGetString(addDoc.RootElement, "credentialId", "CredentialId");
        Assert.False(string.IsNullOrEmpty(credentialId));

        var listed = await ReadPasskeysAsync(await client.GetAsync("/account/passkeys/"));
        var stored = Assert.Single(listed);
        Assert.Equal(credentialId, stored.Id);
        Assert.Equal("Laptop", stored.Name);

        var renamed = await SendAsync(
            client,
            HttpMethod.Patch,
            "/account/passkeys/",
            new { id = credentialId, newName = "  Phone  " },
            csrfOnMutations,
            reauth);
        Assert.Equal(HttpStatusCode.OK, renamed.StatusCode);
        var afterRename = Assert.Single(await ReadPasskeysAsync(await client.GetAsync("/account/passkeys/")));
        Assert.Equal("Phone", afterRename.Name);

        var tooLong = await SendAsync(
            client,
            HttpMethod.Patch,
            "/account/passkeys/",
            new { id = credentialId, newName = new string('a', PasskeyHttp.NameMaxLength + 1) },
            csrfOnMutations,
            reauth);
        await TestHelpers.AssertValidationErrorAsync(tooLong, "Name");
        Assert.Equal("Phone", Assert.Single(await ReadPasskeysAsync(await client.GetAsync("/account/passkeys/"))).Name);

        var cleared = await SendAsync(
            client,
            HttpMethod.Patch,
            "/account/passkeys/",
            new { id = credentialId, newName = "   " },
            csrfOnMutations,
            reauth);
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);
        Assert.Null(Assert.Single(await ReadPasskeysAsync(await client.GetAsync("/account/passkeys/"))).Name);

        var deleted = await SendAsync(
            client,
            HttpMethod.Delete,
            $"/account/passkeys/{credentialId}",
            body: null,
            csrfOnMutations,
            reauth);
        var deletedBody = await deleted.Content.ReadAsStringAsync();
        Assert.True(deleted.StatusCode == HttpStatusCode.OK, deletedBody);
        Assert.Empty(await ReadPasskeysAsync(await client.GetAsync("/account/passkeys/")));
    }

    [Fact]
    public async Task ReauthCredentialAlone_CannotListOrDelete()
    {
        using var factory = new TestWebApplicationFactory();
        var email = $"pk-reauth-only-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);
        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();

        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        var reauth = await TestHelpers.ConfirmIdentityAsync(client, new { password = TestHelpers.DefaultPassword });
        var credentialId = await AddPasskeyAsync(client, authenticator, origin, reauth);

        using var headerOnly = factory.CreateClient();
        headerOnly.DefaultRequestHeaders.TryAddWithoutValidation("X-AuthEndpoints-Reauth", reauth);
        var list = await headerOnly.GetAsync("/account/passkeys/");
        Assert.Equal(HttpStatusCode.Unauthorized, list.StatusCode);

        var delete = await headerOnly.DeleteAsync($"/account/passkeys/{credentialId}");
        Assert.Equal(HttpStatusCode.Unauthorized, delete.StatusCode);
        Assert.Single(await ReadPasskeysAsync(await client.GetAsync("/account/passkeys/")));

        Assert.True(
            (await TestHelpers.PostWithCsrfAsync(client, "/identity/confirmIdentity", new { password = TestHelpers.DefaultPassword }))
                .Headers.TryGetValues("Set-Cookie", out var setCookies));
        var reauthCookie = setCookies!.Select(value => value.Split(';', 2)[0].Trim())
            .FirstOrDefault(pair => pair.StartsWith("AuthEndpoints.ReAuth=", StringComparison.Ordinal));
        Assert.False(string.IsNullOrEmpty(reauthCookie));

        using var cookieOnly = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false
        });
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"/account/passkeys/{credentialId}");
        request.Headers.TryAddWithoutValidation("Cookie", reauthCookie);
        var cookieDelete = await cookieOnly.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, cookieDelete.StatusCode);
        Assert.Single(await ReadPasskeysAsync(await client.GetAsync("/account/passkeys/")));
    }

    private static async Task SignInAsync(HttpClient client, string mode, string email)
    {
        switch (mode)
        {
            case "cookie":
                await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
                break;
            case "identity-bearer":
                var (accessToken, _) = await TestHelpers.LoginBearerAsync(client, email, TestHelpers.DefaultPassword);
                TestHelpers.SetBearer(client, accessToken);
                break;
            case "jwt":
                TestHelpers.SetBearer(client, await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown sign-in mode.");
        }
    }

    private static async Task<string> ConfirmAsync(HttpClient client, bool csrf)
    {
        var proof = new { password = TestHelpers.DefaultPassword };
        var response = csrf
            ? await TestHelpers.PostWithCsrfAsync(client, "/identity/confirmIdentity", proof)
            : await client.PostAsJsonAsync("/identity/confirmIdentity", proof);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        using var doc = JsonDocument.Parse(body);
        var token = TestHelpers.TryGetString(doc.RootElement, "reauthToken", "ReauthToken");
        Assert.False(string.IsNullOrEmpty(token));
        return token!;
    }

    private static async Task<string> AddPasskeyAsync(
        HttpClient client,
        SoftwareWebAuthnAuthenticator authenticator,
        string origin,
        string reauth)
    {
        var options = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/creationOptions",
            new { },
            reauth);
        var optionsBody = await options.Content.ReadAsStringAsync();
        Assert.True(options.StatusCode == HttpStatusCode.OK, optionsBody);
        var credentialJson = authenticator.CreateAttestation(optionsBody, origin);
        var add = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/",
            new { credentialJson, name = "Laptop" },
            reauth);
        var addBody = await add.Content.ReadAsStringAsync();
        Assert.True(add.StatusCode == HttpStatusCode.OK, addBody);
        using var doc = JsonDocument.Parse(addBody);
        return TestHelpers.TryGetString(doc.RootElement, "credentialId", "CredentialId")!;
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient client,
        HttpMethod method,
        string url,
        object? body,
        bool csrf,
        string? reauth)
    {
        if (csrf)
        {
            return await TestHelpers.SendWithCsrfAsync(client, method, url, body, reauth);
        }

        using var request = new HttpRequestMessage(method, url)
        {
            Content = body is null ? null : JsonContent.Create(body)
        };
        if (!string.IsNullOrEmpty(reauth))
        {
            request.Headers.TryAddWithoutValidation("X-AuthEndpoints-Reauth", reauth);
        }

        return await client.SendAsync(request);
    }

    private static async Task<List<ListedPasskey>> ReadPasskeysAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        using var doc = JsonDocument.Parse(body);
        var passkeys = doc.RootElement.TryGetProperty("passkeys", out var camel)
            ? camel
            : doc.RootElement.GetProperty("Passkeys");
        var listed = new List<ListedPasskey>();
        foreach (var item in passkeys.EnumerateArray())
        {
            listed.Add(new ListedPasskey(
                TestHelpers.TryGetString(item, "credentialId", "CredentialId"),
                TestHelpers.TryGetString(item, "displayName", "DisplayName")));
        }

        return listed;
    }

    private sealed record ListedPasskey(string? Id, string? Name);
}
