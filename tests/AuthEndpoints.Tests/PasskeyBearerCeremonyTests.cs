using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

public class PasskeyBearerCeremonyTests
{
    [Fact]
    public async Task AnonymousPasskeyRoutes_OnBearerFacade_SetAndReadCeremonyCookie_SoCsrfStaysRequired()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = root.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AE_HOST_MODE", "bearer-facade");
            builder.UseSetting("AE_FACADE_JWT", "false");
        });

        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var email = $"pk-bearer-ceremony-{Guid.NewGuid():N}@test.local";

        var requestOptions = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/requestOptions",
            new { email },
            csrfPath: "/test/csrfToken");
        Assert.Equal(HttpStatusCode.OK, requestOptions.StatusCode);
        Assert.Contains(
            IdentityConstants.TwoFactorUserIdScheme,
            ReadSetCookies(requestOptions),
            StringComparison.Ordinal);

        var registerOptions = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register/options",
            new { email },
            csrfPath: "/test/csrfToken");
        var registerOptionsBody = await registerOptions.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, registerOptions.StatusCode);
        Assert.Contains(
            IdentityConstants.TwoFactorUserIdScheme,
            ReadSetCookies(registerOptions),
            StringComparison.Ordinal);

        using var withoutCeremonyCookie = TestHelpers.CreateClientWithCookies(factory);
        var credentialJson = authenticator.CreateAttestation(registerOptionsBody, origin);
        var missingState = await TestHelpers.PostWithCsrfAsync(
            withoutCeremonyCookie,
            "/account/passkeys/register",
            new { email, credentialJson },
            csrfPath: "/test/csrfToken");
        await TestHelpers.AssertValidationErrorAsync(missingState, "InvalidPasskeyState");

        // useCookies selects the application cookie. The default bearer sign-in writes the
        // token body inside SignInAsync, so this call is the cookie path: it proves the
        // ceremony cookie is consumed and that register can set an auth cookie.
        var register = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register?useCookies=true",
            new { email, credentialJson },
            csrfPath: "/test/csrfToken");
        var registerBody = await register.Content.ReadAsStringAsync();
        Assert.True(register.StatusCode == HttpStatusCode.OK, registerBody);
        Assert.Contains(
            ".AspNetCore.Identity.Application",
            ReadSetCookies(register),
            StringComparison.Ordinal);
        using var registerDoc = JsonDocument.Parse(registerBody);
        Assert.False(string.IsNullOrEmpty(
            TestHelpers.TryGetString(registerDoc.RootElement, "credentialId", "CredentialId")));

        var loginOptions = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/requestOptions",
            new { email },
            csrfPath: "/test/csrfToken");
        var loginOptionsBody = await loginOptions.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, loginOptions.StatusCode);
        var assertionJson = authenticator.CreateAssertion(loginOptionsBody, origin);

        using var noStateClient = TestHelpers.CreateClientWithCookies(factory);
        var noState = await TestHelpers.PostWithCsrfAsync(
            noStateClient,
            "/account/passkeys/login",
            new { credentialJson = assertionJson },
            csrfPath: "/test/csrfToken");
        await TestHelpers.AssertValidationErrorAsync(noState, "InvalidPasskeyState");

        var login = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/login",
            new { credentialJson = assertionJson },
            csrfPath: "/test/csrfToken");
        var loginBody = await login.Content.ReadAsStringAsync();
        Assert.True(
            login.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            loginBody);
        Assert.DoesNotContain(
            ".AspNetCore.Identity.Application",
            ReadSetCookies(login),
            StringComparison.Ordinal);
        if (login.StatusCode == HttpStatusCode.OK && !string.IsNullOrWhiteSpace(loginBody))
        {
            using var loginDoc = JsonDocument.Parse(loginBody);
            Assert.False(string.IsNullOrEmpty(
                TestHelpers.TryGetString(loginDoc.RootElement, "accessToken", "AccessToken")));
        }

        var cookieLoginOptions = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/requestOptions",
            new { email },
            csrfPath: "/test/csrfToken");
        var cookieAssertion = authenticator.CreateAssertion(
            await cookieLoginOptions.Content.ReadAsStringAsync(),
            origin);
        var cookieLogin = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/login?useCookies=true",
            new { credentialJson = cookieAssertion },
            csrfPath: "/test/csrfToken");
        Assert.True(
            cookieLogin.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            await cookieLogin.Content.ReadAsStringAsync());
        Assert.Contains(
            ".AspNetCore.Identity.Application",
            ReadSetCookies(cookieLogin),
            StringComparison.Ordinal);
    }

    private static string ReadSetCookies(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return string.Empty;
        }

        return string.Join("\n", values);
    }
}
