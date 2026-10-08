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
    public async Task ListAddRenameDelete_RequireSignIn_AndReauthOnMutations(string mode)
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

    [Theory]
    [MemberData(nameof(SignInModes))]
    public async Task ReauthCredentialAlone_IsNotASignIn(string mode)
    {
        using var factory = new TestWebApplicationFactory();
        var email = $"pk-reauth-only-{mode}-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var signedIn = TestHelpers.CreateClientWithCookies(factory);
        await SignInAsync(signedIn, mode, email);
        var (reauth, reauthCookie) = await ConfirmWithCookieAsync(signedIn, csrf: mode == "cookie");

        await AssertReauthOnlyRejectedAsync(factory, reauth, cookie: null);
        if (reauthCookie is not null)
        {
            await AssertReauthOnlyRejectedAsync(factory, reauthToken: null, reauthCookie);
        }
    }

    [Theory]
    [MemberData(nameof(SignInModes))]
    public async Task ReauthForADifferentUser_IsRejected(string mode)
    {
        using var factory = new TestWebApplicationFactory();
        var emailA = $"pk-user-a-{mode}-{Guid.NewGuid():N}@test.local";
        var emailB = $"pk-user-b-{mode}-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, emailA);
        await TestHelpers.SeedUserAsync(factory, emailB);

        using var clientA = TestHelpers.CreateClientWithCookies(factory);
        await SignInAsync(clientA, mode, emailA);
        var (reauthA, _) = await ConfirmWithCookieAsync(clientA, csrf: mode == "cookie");

        using var clientB = TestHelpers.CreateClientWithCookies(factory);
        await SignInAsync(clientB, mode, emailB);

        foreach (var (method, url, body) in ReauthRoutes)
        {
            var response = await SendAsync(clientB, method, url, body, csrf: false, reauthA);
            Assert.True(
                response.StatusCode == HttpStatusCode.Forbidden,
                $"{method} {url} with user B's sign-in and user A's ReAuth returned {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        }

        var list = await SendAsync(clientB, HttpMethod.Get, "/account/passkeys/", body: null, csrf: false, reauthA);
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
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

    private static readonly (HttpMethod Method, string Url, object? Body)[] ReauthRoutes =
    [
        (HttpMethod.Post, "/account/passkeys/creationOptions", new { }),
        (HttpMethod.Post, "/account/passkeys/", new { credentialJson = "{}", name = "Laptop" }),
        (HttpMethod.Patch, "/account/passkeys/", new { id = "abc", newName = "Phone" }),
        (HttpMethod.Delete, "/account/passkeys/abc", null),
        (HttpMethod.Post, "/identity/manage/2fa", new { enable = true, twoFactorCode = "000000" }),
        (HttpMethod.Post, "/identity/manage/info", new { oldPassword = "x", newPassword = "ChangedPass1!" }),
    ];

    private static async Task AssertReauthOnlyRejectedAsync(
        TestWebApplicationFactory factory,
        string? reauthToken,
        string? cookie)
    {
        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false
        });
        if (!string.IsNullOrEmpty(reauthToken))
        {
            client.DefaultRequestHeaders.TryAddWithoutValidation("X-AuthEndpoints-Reauth", reauthToken);
        }

        var routes = ReauthRoutes.Append((HttpMethod.Get, "/account/passkeys/", (object?)null));
        foreach (var (method, url, body) in routes)
        {
            using var request = new HttpRequestMessage(method, url)
            {
                Content = body is null ? null : JsonContent.Create(body)
            };
            if (!string.IsNullOrEmpty(cookie))
            {
                request.Headers.TryAddWithoutValidation("Cookie", cookie);
            }

            var response = await client.SendAsync(request);
            Assert.True(
                response.StatusCode == HttpStatusCode.Unauthorized,
                $"{method} {url} with only a ReAuth credential returned {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        }
    }

    private static async Task<(string Token, string? Cookie)> ConfirmWithCookieAsync(HttpClient client, bool csrf)
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

        string? cookie = null;
        if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            cookie = setCookies.Select(value => value.Split(';', 2)[0].Trim())
                .FirstOrDefault(pair => pair.StartsWith("AuthEndpoints.ReAuth=", StringComparison.Ordinal));
        }

        if (csrf)
        {
            Assert.False(string.IsNullOrEmpty(cookie));
        }
        else
        {
            Assert.True(string.IsNullOrEmpty(cookie));
        }

        return (token!, cookie);
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
