using System.Net;
using System.Text.Json;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

public class PasskeyRemovalTests
{
    [Theory]
    [InlineData(false, 1, 0, false)]
    [InlineData(false, 2, 0, true)]
    [InlineData(true, 1, 0, true)]
    [InlineData(false, 1, 1, true)]
    [InlineData(false, 0, 1, false)]
    public void CanRemove_RefusesOnlyTheLastPasskey(bool hasPassword, int passkeyCount, int externalLogins, bool expected)
    {
        Assert.Equal(expected, PasskeyRemovalPolicy.CanRemove(hasPassword, passkeyCount, externalLogins));
    }

    [Fact]
    public async Task Delete_LastPasskey_WithoutPasswordOrExternalLogin_ReturnsValidationProblem()
    {
        await using var factory = new TestWebApplicationFactory();
        var email = $"pk-last-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var credentialId = await RegisterPasskeyAsync(client, authenticator, origin, email);
        var reauth = await ConfirmWithPasskeyAsync(client, authenticator, origin);

        var delete = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Delete,
            $"/account/passkeys/{credentialId}",
            body: null,
            reauth);
        await TestHelpers.AssertValidationErrorAsync(delete, PasskeyHttp.LastSignInMethod);

        var list = await client.GetAsync("/account/passkeys/");
        using var doc = JsonDocument.Parse(await list.Content.ReadAsStringAsync());
        var passkeys = doc.RootElement.GetProperty("passkeys");
        Assert.Equal(1, passkeys.GetArrayLength());
        Assert.Equal(credentialId, TestHelpers.TryGetString(passkeys[0], "credentialId", "CredentialId"));
    }

    [Fact]
    public async Task Delete_SparePasskey_Succeeds_AndLastRemainingPasskeyIsRefused()
    {
        await using var factory = new TestWebApplicationFactory();
        var email = $"pk-spare-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var firstId = await RegisterPasskeyAsync(client, authenticator, origin, email);
        var reauth = await ConfirmWithPasskeyAsync(client, authenticator, origin);

        var options = await TestHelpers.PostWithCsrfAsync(client, "/account/passkeys/creationOptions", new { }, reauth);
        var optionsBody = await options.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, options.StatusCode);
        var secondJson = authenticator.CreateAttestation(optionsBody, origin);
        var add = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/",
            new { credentialJson = secondJson, name = "Phone" },
            reauth);
        var addBody = await add.Content.ReadAsStringAsync();
        Assert.True(add.StatusCode == HttpStatusCode.OK, addBody);
        using var addDoc = JsonDocument.Parse(addBody);
        var secondId = TestHelpers.TryGetString(addDoc.RootElement, "credentialId", "CredentialId");
        Assert.False(string.IsNullOrEmpty(secondId));

        var deleteFirst = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Delete,
            $"/account/passkeys/{firstId}",
            body: null,
            reauth);
        Assert.Equal(HttpStatusCode.OK, deleteFirst.StatusCode);

        var deleteLast = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Delete,
            $"/account/passkeys/{secondId}",
            body: null,
            reauth);
        await TestHelpers.AssertValidationErrorAsync(deleteLast, PasskeyHttp.LastSignInMethod);
    }

    [Fact]
    public async Task Delete_LastPasskey_WithExternalLogin_Succeeds()
    {
        await using var factory = new TestWebApplicationFactory();
        var email = $"pk-external-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();
        var credentialId = await RegisterPasskeyAsync(client, authenticator, origin, email);

        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = await userManager.FindByEmailAsync(email);
            Assert.NotNull(user);
            var login = await userManager.AddLoginAsync(user, new UserLoginInfo("Contoso", "user-1", "Contoso"));
            Assert.True(login.Succeeded, string.Join("; ", login.Errors.Select(error => error.Description)));
        }

        var reauth = await ConfirmWithPasskeyAsync(client, authenticator, origin);
        var delete = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Delete,
            $"/account/passkeys/{credentialId}",
            body: null,
            reauth);
        var body = await delete.Content.ReadAsStringAsync();
        Assert.True(delete.StatusCode == HttpStatusCode.OK, body);
    }

    private static async Task<string> RegisterPasskeyAsync(
        HttpClient client,
        SoftwareWebAuthnAuthenticator authenticator,
        string origin,
        string email)
    {
        var options = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register/options",
            new { email });
        var optionsBody = await options.Content.ReadAsStringAsync();
        Assert.True(options.StatusCode == HttpStatusCode.OK, optionsBody);
        var credentialJson = authenticator.CreateAttestation(optionsBody, origin);
        var register = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register?useCookies=true",
            new { email, credentialJson });
        var body = await register.Content.ReadAsStringAsync();
        Assert.True(register.StatusCode == HttpStatusCode.OK, body);
        using var doc = JsonDocument.Parse(body);
        var credentialId = TestHelpers.TryGetString(doc.RootElement, "credentialId", "CredentialId");
        Assert.False(string.IsNullOrEmpty(credentialId));

        var info = await client.GetAsync("/identity/manage/info");
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
        return credentialId!;
    }

    private static async Task<string> ConfirmWithPasskeyAsync(
        HttpClient client,
        SoftwareWebAuthnAuthenticator authenticator,
        string origin)
    {
        var options = await TestHelpers.PostWithCsrfAsync(client, "/identity/confirmIdentity/passkeyOptions", new { });
        var optionsBody = await options.Content.ReadAsStringAsync();
        Assert.True(options.StatusCode == HttpStatusCode.OK, optionsBody);
        var credentialJson = authenticator.CreateAssertion(optionsBody, origin);
        return await TestHelpers.ConfirmIdentityAsync(client, new { credentialJson });
    }
}
