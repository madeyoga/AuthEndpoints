using System.Net;
using System.Text.Json;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;

namespace AuthEndpoints.Tests;

public class PasskeyRegisterResponseTests
{
    public static TheoryData<string, bool, bool> FacadeRegisterCases()
    {
        var data = new TheoryData<string, bool, bool>();
        foreach (var mode in new[] { "cookie", "bearer", "jwt" })
        {
            foreach (var requireConfirmed in new[] { true, false })
            {
                foreach (var useCookies in new[] { true, false })
                {
                    data.Add(mode, requireConfirmed, useCookies);
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(FacadeRegisterCases))]
    public async Task Register_ReturnsCredentialOrToken_AndDoesNotThrow(
        string mode,
        bool requireConfirmed,
        bool useCookies)
    {
        await using var root = new TestWebApplicationFactory();
        var configured = requireConfirmed ? root.WithRequireConfirmedAccount() : root;
        using var factory = configured.WithWebHostBuilder(builder =>
        {
            var hostMode = mode == "bearer" ? "bearer-facade" : "cookie-facade";
            builder.UseSetting("AE_HOST_MODE", hostMode);
            if (mode == "jwt")
            {
                builder.UseSetting("AE_FACADE_JWT", "true");
                builder.ConfigureServices(services =>
                {
                    services.AddPasskeySignInCompleter<TestAppUser, JwtPasskeySignInCompleter<TestAppUser>>();
                });
            }
        });

        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var email = $"pk-reg-{mode}-{requireConfirmed}-{useCookies}-{Guid.NewGuid():N}@test.local";
        var csrfPath = mode == "bearer" ? "/test/csrfToken" : "/identity/csrfToken";

        var optionsResponse = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register/options",
            new { email },
            csrfPath: csrfPath);
        Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);

        var credentialJson = authenticator.CreateAttestation(
            await optionsResponse.Content.ReadAsStringAsync(),
            origin);
        var registerPath = useCookies
            ? "/account/passkeys/register?useCookies=true"
            : "/account/passkeys/register";
        var register = await TestHelpers.PostWithCsrfAsync(
            client,
            registerPath,
            new { email, credentialJson },
            csrfPath: csrfPath);
        var body = await register.Content.ReadAsStringAsync();
        Assert.True(
            register.StatusCode == HttpStatusCode.OK,
            $"mode={mode} confirmed={requireConfirmed} useCookies={useCookies} status={(int)register.StatusCode} body={body}");
        Assert.DoesNotContain("already started", body, StringComparison.OrdinalIgnoreCase);

        using var doc = JsonDocument.Parse(body);
        var credentialId = TestHelpers.TryGetString(doc.RootElement, "credentialId", "CredentialId");
        var accessToken = TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken");
        var cookieSignIn = mode != "jwt" && useCookies;
        var sessionIssued = !requireConfirmed;

        if (requireConfirmed || cookieSignIn)
        {
            Assert.False(string.IsNullOrEmpty(credentialId));
            Assert.True(string.IsNullOrEmpty(accessToken));
        }
        else
        {
            Assert.False(string.IsNullOrEmpty(accessToken));
            Assert.True(string.IsNullOrEmpty(credentialId));
        }

        if (mode == "jwt" && sessionIssued)
        {
            Assert.Equal("Bearer", TestHelpers.TryGetString(doc.RootElement, "tokenType", "TokenType"));
        }

        Assert.Equal(cookieSignIn && sessionIssued, HasSetCookie(register, ".AspNetCore.Identity.Application"));
        Assert.Equal(mode == "jwt" && sessionIssued, HasSetCookie(register, RefreshTokenCookieWriter.CookieName));

        if (sessionIssued && !cookieSignIn)
        {
            TestHelpers.SetBearer(client, accessToken!);
        }

        var info = await client.GetAsync("/identity/manage/info");
        if (sessionIssued)
        {
            Assert.Equal(HttpStatusCode.OK, info.StatusCode);
            using var infoDoc = JsonDocument.Parse(await info.Content.ReadAsStringAsync());
            Assert.Equal(email, TestHelpers.TryGetString(infoDoc.RootElement, "email", "Email"));
        }
        else
        {
            Assert.Equal(HttpStatusCode.Unauthorized, info.StatusCode);
        }
    }

    private static bool HasSetCookie(HttpResponseMessage response, string name)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return false;
        }

        return values.Any(value => value.Contains(name, StringComparison.Ordinal));
    }
}
