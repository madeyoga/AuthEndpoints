using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthEndpoints.Tests;

public class PasskeyCsrfWithoutJwtTests
{
    public static TheoryData<string, string> FacadeHosts => new()
    {
        { "cookie-facade", "/identity/csrfToken" },
        { "bearer-facade", "/test/csrfToken" }
    };

    public static TheoryData<string, string> AnonymousPasskeyRequests => new()
    {
        { "cookie-facade", "/account/passkeys/requestOptions" },
        { "cookie-facade", "/account/passkeys/register/options" },
        { "cookie-facade", "/account/passkeys/register" },
        { "cookie-facade", "/account/passkeys/login" },
        { "bearer-facade", "/account/passkeys/requestOptions" },
        { "bearer-facade", "/account/passkeys/register/options" },
        { "bearer-facade", "/account/passkeys/register" },
        { "bearer-facade", "/account/passkeys/login" }
    };

    [Theory]
    [MemberData(nameof(AnonymousPasskeyRequests))]
    public async Task AnonymousPasskeyEndpoint_WithoutCsrf_Returns400(string hostMode, string path)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateFacadeFactory(root, hostMode, jwtEnabled: false);
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
    [MemberData(nameof(FacadeHosts))]
    public async Task RequestOptions_WithCsrf_ReturnsOptions(string hostMode, string csrfPath)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateFacadeFactory(root, hostMode, jwtEnabled: false);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var response = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/requestOptions",
            new { },
            csrfPath: csrfPath);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("challenge", out _));
    }

    [Theory]
    [MemberData(nameof(FacadeHosts))]
    public async Task PasskeyRegisterAndLogin_WithCsrf_Succeeds(string hostMode, string csrfPath)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateFacadeFactory(root, hostMode, jwtEnabled: false);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var email = $"passkey-nojwt-{Guid.NewGuid():N}@test.local";

        using (var registerClient = TestHelpers.CreateClientWithCookies(factory))
        {
            var origin = registerClient.BaseAddress!.GetLeftPart(UriPartial.Authority);
            var optionsResponse = await TestHelpers.PostWithCsrfAsync(
                registerClient,
                "/account/passkeys/register/options",
                new { email },
                csrfPath: csrfPath);
            Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);

            var credentialJson = authenticator.CreateAttestation(
                await optionsResponse.Content.ReadAsStringAsync(),
                origin);
            var register = await TestHelpers.PostWithCsrfAsync(
                registerClient,
                "/account/passkeys/register?useCookies=true",
                new { email, credentialJson },
                csrfPath: csrfPath);
            Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        }

        using var loginClient = TestHelpers.CreateClientWithCookies(factory);
        var loginOrigin = loginClient.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var requestOptions = await TestHelpers.PostWithCsrfAsync(
            loginClient,
            "/account/passkeys/requestOptions",
            new { email },
            csrfPath: csrfPath);
        Assert.Equal(HttpStatusCode.OK, requestOptions.StatusCode);

        var assertionJson = authenticator.CreateAssertion(
            await requestOptions.Content.ReadAsStringAsync(),
            loginOrigin);
        var useCookies = hostMode == "cookie-facade";
        var login = await TestHelpers.PostWithCsrfAsync(
            loginClient,
            useCookies ? "/account/passkeys/login?useCookies=true" : "/account/passkeys/login",
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
        using var factory = CreateFacadeFactory(root, "bearer-facade", jwtEnabled: false);
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
        using var factory = CreateFacadeFactory(root, "cookie-facade", jwtEnabled: false);
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
    public async Task JwtEnabledFacade_RequestOptions_EnforcesCsrf()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateFacadeFactory(root, "bearer-facade", jwtEnabled: true);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var withoutToken = await client.PostAsJsonAsync("/account/passkeys/requestOptions", new { });
        Assert.Equal(HttpStatusCode.BadRequest, withoutToken.StatusCode);

        var withToken = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/requestOptions",
            new { },
            csrfPath: "/test/csrfToken");
        Assert.Equal(HttpStatusCode.OK, withToken.StatusCode);
    }

    private static WebApplicationFactory<Program> CreateFacadeFactory(
        TestWebApplicationFactory root,
        string hostMode,
        bool jwtEnabled) =>
        root.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AE_HOST_MODE", hostMode);
            builder.UseSetting("AE_FACADE_JWT", jwtEnabled ? "true" : "false");
        });
}
