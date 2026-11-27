using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthEndpoints.Tests;

public class PasskeyCsrfWithoutJwtTests
{
    public static TheoryData<string, string> BuilderHosts => new()
    {
        { "builder-cookie", "/identity/csrfToken" },
        { "builder-bearer", "/test/csrfToken" }
    };

    public static TheoryData<string, string> AnonymousPasskeyRequests => new()
    {
        { "builder-cookie", "/identity/passkeys/requestOptions" },
        { "builder-cookie", "/identity/passkeys/register/options" },
        { "builder-cookie", "/identity/passkeys/register" },
        { "builder-cookie", "/identity/passkeys/login" }
    };

    [Theory]
    [MemberData(nameof(AnonymousPasskeyRequests))]
    public async Task AnonymousPasskeyEndpoint_WithoutCsrf_Returns400(string hostMode, string path)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateBuilderFactory(root, hostMode);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var response = await client.PostAsJsonAsync(path, new
        {
            email = $"no-csrf-{Guid.NewGuid():N}@test.local",
            credentialJson = "{}"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("CSRF", body, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [MemberData(nameof(BuilderHosts))]
    public async Task RequestOptions_WithCsrf_ReturnsOptions(string hostMode, string csrfPath)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateBuilderFactory(root, hostMode);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var response = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/passkeys/requestOptions",
            new { },
            csrfPath: csrfPath);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("challenge", out _));
    }

    [Theory]
    [MemberData(nameof(BuilderHosts))]
    public async Task PasskeyRegisterAndLogin_WithCsrf_Succeeds(string hostMode, string csrfPath)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateBuilderFactory(root, hostMode);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var email = $"passkey-nojwt-{Guid.NewGuid():N}@test.local";

        using (var registerClient = TestHelpers.CreateClientWithCookies(factory))
        {
            var origin = registerClient.BaseAddress!.GetLeftPart(UriPartial.Authority);
            var optionsResponse = await TestHelpers.PostWithCsrfAsync(
                registerClient,
                "/identity/passkeys/register/options",
                new { email },
                csrfPath: csrfPath);
            Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);

            var credentialJson = authenticator.CreateAttestation(
                await optionsResponse.Content.ReadAsStringAsync(),
                origin);
            var register = await TestHelpers.PostWithCsrfAsync(
                registerClient,
                "/identity/passkeys/register?useCookies=true",
                new { email, credentialJson },
                csrfPath: csrfPath);
            Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        }

        using var loginClient = TestHelpers.CreateClientWithCookies(factory);
        var loginOrigin = loginClient.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var requestOptions = await TestHelpers.PostWithCsrfAsync(
            loginClient,
            "/identity/passkeys/requestOptions",
            new { email },
            csrfPath: csrfPath);
        Assert.Equal(HttpStatusCode.OK, requestOptions.StatusCode);

        var assertionJson = authenticator.CreateAssertion(
            await requestOptions.Content.ReadAsStringAsync(),
            loginOrigin);
        var useCookies = hostMode == "builder-cookie";
        var login = await TestHelpers.PostWithCsrfAsync(
            loginClient,
            useCookies ? "/identity/passkeys/login?useCookies=true" : "/identity/passkeys/login",
            new { credentialJson = assertionJson },
            csrfPath: csrfPath);
        Assert.True(
            login.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"Passkey login failed: {(int)login.StatusCode} {await login.Content.ReadAsStringAsync()}");

        if (useCookies)
        {
            var info = await loginClient.GetAsync("/identity/manage/info");
            Assert.Equal(HttpStatusCode.OK, info.StatusCode);
        }
        else
        {
            using var doc = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
            Assert.False(string.IsNullOrEmpty(
                TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken")));
        }
    }

    [Fact]
    public async Task IdentityBearerCaller_CsrfProtectedEndpoint_WithoutToken_SucceedsWithoutJwt()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateBuilderFactory(root, "builder-bearer");
        var email = $"bearer-nojwt-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var client = factory.CreateClient();
        var login = await client.PostAsJsonAsync(
            "/identity/login",
            new { email, password = TestHelpers.DefaultPassword });
        login.EnsureSuccessStatusCode();
        using var loginDoc = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        TestHelpers.SetBearer(client, TestHelpers.TryGetString(loginDoc.RootElement, "accessToken", "AccessToken")!);

        var response = await client.PostAsJsonAsync(
            "/identity/confirmIdentity",
            new { password = TestHelpers.DefaultPassword });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CookieCaller_CsrfProtectedEndpoint_WithoutToken_Returns400WithoutJwt()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateBuilderFactory(root, "builder-cookie");
        var email = $"cookie-nojwt-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var client = TestHelpers.CreateClientWithCookies(factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var withoutToken = await client.PostAsync("/identity/logout", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, withoutToken.StatusCode);

        var withToken = await TestHelpers.PostWithCsrfAsync(client, "/identity/logout", body: null);
        Assert.Equal(HttpStatusCode.OK, withToken.StatusCode);
    }

    [Fact]
    public async Task JwtBodyRefreshBuilder_RequestOptions_DoesNotRequireCsrf()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateBuilderFactory(root, "builder-jwt", jwtBodyRefresh: true);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var withoutToken = await client.PostAsJsonAsync("/identity/passkeys/requestOptions", new { });
        Assert.Equal(HttpStatusCode.OK, withoutToken.StatusCode);
        using var doc = JsonDocument.Parse(await withoutToken.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("challenge", out _));
    }

    [Fact]
    public async Task BearerBuilder_PasskeyRegisterAndLogin_WithoutCsrf_Succeeds()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateBuilderFactory(root, "builder-bearer");
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var email = $"passkey-bearer-nocsrf-{Guid.NewGuid():N}@test.local";

        using var registerClient = TestHelpers.CreateClientWithCookies(factory);
        var origin = registerClient.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var optionsResponse = await registerClient.PostAsJsonAsync(
            "/identity/passkeys/register/options",
            new { email });
        Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);

        var credentialJson = authenticator.CreateAttestation(
            await optionsResponse.Content.ReadAsStringAsync(),
            origin);
        var register = await registerClient.PostAsJsonAsync(
            "/identity/passkeys/register",
            new { email, credentialJson });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        using var registerDoc = JsonDocument.Parse(await register.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(
            TestHelpers.TryGetString(registerDoc.RootElement, "accessToken", "AccessToken")));

        using var loginClient = TestHelpers.CreateClientWithCookies(factory);
        var loginOrigin = loginClient.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var requestOptions = await loginClient.PostAsJsonAsync(
            "/identity/passkeys/requestOptions",
            new { email });
        Assert.Equal(HttpStatusCode.OK, requestOptions.StatusCode);

        var assertionJson = authenticator.CreateAssertion(
            await requestOptions.Content.ReadAsStringAsync(),
            loginOrigin);
        var login = await loginClient.PostAsJsonAsync(
            "/identity/passkeys/login",
            new { credentialJson = assertionJson });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var loginDoc = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(
            TestHelpers.TryGetString(loginDoc.RootElement, "accessToken", "AccessToken")));
    }

    private static WebApplicationFactory<Program> CreateBuilderFactory(
        TestWebApplicationFactory root,
        string hostMode,
        bool jwtBodyRefresh = false) =>
        root.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AE_HOST_MODE", hostMode);
            builder.UseSetting("AE_BUILDER_PATH", "/identity");
            builder.UseSetting("AE_REQUIRE_CONFIRMED_ACCOUNT", "false");
            if (jwtBodyRefresh)
            {
                builder.UseSetting("AE_JWT_REFRESH_TRANSPORT", "Body");
            }
        });
}
