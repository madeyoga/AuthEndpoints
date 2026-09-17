using System.Net;
using System.Text;
using System.Text.Json;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

public class PasskeyEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public PasskeyEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task RegisterOptions_Default_MintsGuidShapedUserId()
    {
        var email = $"passkey-guid-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/passkeys/register/options")
        {
            Content = JsonContent.Create(new { email })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var userId = ReadCreationOptionsUserId(await response.Content.ReadAsStringAsync());
        Assert.True(Guid.TryParse(userId, out _), $"Expected a Guid-shaped id, got '{userId}'.");
    }

    [Fact]
    public async Task RegisterOptions_RegisteredFactory_UsesFactoryId()
    {
        const string expectedId = "factory-minted-user-id";
        using var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.AddPasskeyUserIdFactory(() => expectedId);
            });
        });

        var email = $"passkey-factory-{Guid.NewGuid():N}@test.local";
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/passkeys/register/options")
        {
            Content = JsonContent.Create(new { email })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var userId = ReadCreationOptionsUserId(await response.Content.ReadAsStringAsync());
        Assert.Equal(expectedId, userId);
    }

    [Fact]
    public async Task RegisterOptions_ExistingEmail_ReturnsOptionsJson()
    {
        var email = $"passkey-enum-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/passkeys/register/options")
        {
            Content = JsonContent.Create(new { email })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("already exists", body, StringComparison.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Fact]
    public async Task Register_ExistingUserId_ReturnsGenericBadRequestWithoutAttachingPasskey()
    {
        var existingUserId = Guid.NewGuid().ToString();
        var existingEmail = $"passkey-existing-id-{Guid.NewGuid():N}@test.local";
        var freeEmail = $"passkey-free-{Guid.NewGuid():N}@test.local";

        using var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.AddPasskeyUserIdFactory(() => existingUserId);
            });
        });

        int passkeyCountBefore;
        using (var seedScope = factory.Services.CreateScope())
        {
            var userManager = seedScope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var seeded = new TestAppUser
            {
                Id = existingUserId,
                UserName = existingEmail,
                Email = existingEmail,
                EmailConfirmed = true
            };
            var create = await userManager.CreateAsync(seeded, TestHelpers.DefaultPassword);
            Assert.True(create.Succeeded, string.Join("; ", create.Errors.Select(e => e.Description)));
            passkeyCountBefore = (await userManager.GetPasskeysAsync(seeded)).Count;
        }

        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();

        var optionsResponse = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register/options",
            new { email = freeEmail });
        Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);
        var optionsJson = await optionsResponse.Content.ReadAsStringAsync();
        Assert.Equal(existingUserId, ReadCreationOptionsUserId(optionsJson));

        var credentialJson = authenticator.CreateAttestation(optionsJson, origin);
        var register = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register",
            new { email = freeEmail, credentialJson });
        Assert.Equal(HttpStatusCode.BadRequest, register.StatusCode);

        var body = await register.Content.ReadAsStringAsync();
        Assert.Contains("Unable to complete registration", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("already exists", body, StringComparison.OrdinalIgnoreCase);

        using var afterScope = factory.Services.CreateScope();
        var afterUserManager = afterScope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var existing = await afterUserManager.FindByIdAsync(existingUserId);
        Assert.NotNull(existing);
        Assert.Equal(existingEmail, await afterUserManager.GetEmailAsync(existing));
        Assert.Equal(passkeyCountBefore, (await afterUserManager.GetPasskeysAsync(existing)).Count);
        Assert.Null(await afterUserManager.FindByEmailAsync(freeEmail));
    }

    [Fact]
    public async Task Register_ExistingEmail_ReturnsGenericBadRequest()
    {
        var email = $"passkey-reg-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/passkeys/register")
        {
            Content = JsonContent.Create(new
            {
                email,
                credentialJson = "{}"
            })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Unable to complete registration", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("already exists", body, StringComparison.OrdinalIgnoreCase);

        var mailbox = _factory.Services.GetRequiredService<CapturingEmailSender>();
        Assert.DoesNotContain(mailbox.Snapshot(), mail => mail.Email == email);
    }

    [Fact]
    public async Task Register_NewUnconfirmedUser_SendsConfirmationEmailWithoutSession()
    {
        using var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AE_REQUIRE_CONFIRMED_ACCOUNT", "true");
        });

        var email = $"passkey-confirm-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();

        var optionsResponse = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register/options",
            new { email });
        Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);
        var optionsJson = await optionsResponse.Content.ReadAsStringAsync();
        var credentialJson = authenticator.CreateAttestation(optionsJson, origin);

        var register = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register?useCookies=true",
            new { email, credentialJson });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        if (register.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            Assert.DoesNotContain(
                cookies,
                static c => c.Contains(".AspNetCore.Identity.Application", StringComparison.Ordinal));
        }

        using var registerDoc = JsonDocument.Parse(await register.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(
            TestHelpers.TryGetString(registerDoc.RootElement, "credentialId", "CredentialId")));

        var info = await client.GetAsync("/identity/manage/info");
        Assert.Equal(HttpStatusCode.Unauthorized, info.StatusCode);

        var mailbox = factory.Services.GetRequiredService<CapturingEmailSender>();
        var mail = Assert.Single(mailbox.Snapshot(), item => item.Email == email && item.Kind == "confirm");
        Assert.Contains("/identity/confirmEmail", mail.Body, StringComparison.OrdinalIgnoreCase);

        var confirmUri = new Uri(System.Net.WebUtility.HtmlDecode(mail.Body));
        var confirm = await client.GetAsync(confirmUri.PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        var requestOptions = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/requestOptions",
            new { });
        Assert.Equal(HttpStatusCode.OK, requestOptions.StatusCode);
        var assertionJson = authenticator.CreateAssertion(
            await requestOptions.Content.ReadAsStringAsync(),
            origin);

        var login = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/login?useCookies=true",
            new { credentialJson = assertionJson });
        Assert.True(
            login.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"Passkey login after confirm failed: {(int)login.StatusCode} {await login.Content.ReadAsStringAsync()}");

        var signedIn = await client.GetAsync("/identity/manage/info");
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        using var infoDoc = JsonDocument.Parse(await signedIn.Content.ReadAsStringAsync());
        Assert.Equal(email, TestHelpers.TryGetString(infoDoc.RootElement, "email", "Email"));
        Assert.True(TestHelpers.TryGetBool(infoDoc.RootElement, "isEmailConfirmed", "IsEmailConfirmed", out var confirmed) && confirmed);
    }

    [Fact]
    public async Task Register_FailedAttestation_DoesNotSendConfirmationEmail()
    {
        var email = $"passkey-bad-attest-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var options = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register/options",
            new { email });
        Assert.Equal(HttpStatusCode.OK, options.StatusCode);

        var response = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register",
            new { email, credentialJson = "{}" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var mailbox = _factory.Services.GetRequiredService<CapturingEmailSender>();
        Assert.DoesNotContain(mailbox.Snapshot(), mail => mail.Email == email);
    }

    internal static string ReadCreationOptionsUserId(string optionsJson)
    {
        using var doc = JsonDocument.Parse(optionsJson);
        Assert.True(
            doc.RootElement.TryGetProperty("user", out var user)
            || doc.RootElement.TryGetProperty("User", out user),
            "Expected user in creation options JSON.");

        var id = TestHelpers.TryGetString(user, "id", "Id");
        Assert.False(string.IsNullOrWhiteSpace(id), "Expected user.id in creation options JSON.");

        if (Guid.TryParse(id, out _))
        {
            return id;
        }

        try
        {
            var bytes = WebEncoders.Base64UrlDecode(id);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (FormatException)
        {
            return id;
        }
    }

    [Fact]
    public async Task AddPasskey_UserEntityMismatch_ReturnsUserMismatchAndDoesNotStore()
    {
        using var factory = new TestWebApplicationFactory();
        var email = $"pk-mismatch-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);
        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();

        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        var reauth = await TestHelpers.ConfirmIdentityAsync(
            client,
            new { password = TestHelpers.DefaultPassword });

        var optionsResponse = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register/options",
            new { email = $"pk-other-{Guid.NewGuid():N}@test.local" });
        Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);
        var optionsJson = await optionsResponse.Content.ReadAsStringAsync();
        var credentialJson = authenticator.CreateAttestation(optionsJson, origin);

        var add = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/",
            new { credentialJson, name = "ShouldNotStore" },
            reauth);
        await TestHelpers.AssertValidationErrorAsync(add, PasskeyHttp.UserMismatch);

        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        Assert.NotNull(user);
        Assert.Empty(await userManager.GetPasskeysAsync(user));
    }

    [Fact]
    public async Task AddPasskey_WithName_ListShowsDisplayNameAndCreatedAt_ThenDeleteAndRenameMiss()
    {
        using var factory = new TestWebApplicationFactory();
        var email = $"pk-manage-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);
        using var client = TestHelpers.CreateClientWithCookies(factory);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var authenticator = factory.Services.GetRequiredService<SoftwareWebAuthnAuthenticator>();

        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        var reauth = await TestHelpers.ConfirmIdentityAsync(
            client,
            new { password = TestHelpers.DefaultPassword });

        var optionsResponse = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/creationOptions",
            new { },
            reauth);
        Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);
        var credentialJson = authenticator.CreateAttestation(
            await optionsResponse.Content.ReadAsStringAsync(),
            origin);

        var beforeAdd = DateTimeOffset.UtcNow.AddMinutes(-1);
        var add = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/",
            new { credentialJson, name = "  Laptop  " },
            reauth);
        Assert.Equal(HttpStatusCode.OK, add.StatusCode);
        using var addDoc = JsonDocument.Parse(await add.Content.ReadAsStringAsync());
        Assert.Equal("Laptop", TestHelpers.TryGetString(addDoc.RootElement, "displayName", "DisplayName"));
        var addCreatedAt = TestHelpers.TryGetDateTimeOffset(addDoc.RootElement, "createdAt", "CreatedAt");
        Assert.NotNull(addCreatedAt);
        Assert.InRange(addCreatedAt.Value, beforeAdd, DateTimeOffset.UtcNow.AddMinutes(1));
        var credentialId = TestHelpers.TryGetString(addDoc.RootElement, "credentialId", "CredentialId");
        Assert.False(string.IsNullOrEmpty(credentialId));

        var list = await client.GetAsync("/account/passkeys/");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        using var listDoc = JsonDocument.Parse(await list.Content.ReadAsStringAsync());
        var passkeys = listDoc.RootElement.TryGetProperty("passkeys", out var p)
            ? p
            : listDoc.RootElement.GetProperty("Passkeys");
        Assert.Equal(1, passkeys.GetArrayLength());
        var listed = passkeys[0];
        Assert.Equal(credentialId, TestHelpers.TryGetString(listed, "credentialId", "CredentialId"));
        Assert.Equal("Laptop", TestHelpers.TryGetString(listed, "displayName", "DisplayName"));
        Assert.NotNull(TestHelpers.TryGetDateTimeOffset(listed, "createdAt", "CreatedAt"));

        var unknownId = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("missing-passkey-id"));
        var deleteMiss = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Delete,
            $"/account/passkeys/{unknownId}",
            body: null,
            reauth);
        Assert.Equal(HttpStatusCode.NotFound, deleteMiss.StatusCode);

        var deleteGarbage = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Delete,
            "/account/passkeys/not-valid!!!",
            body: null,
            reauth);
        await TestHelpers.AssertValidationErrorAsync(deleteGarbage, PasskeyHttp.InvalidCredentialId);

        var renameMiss = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Patch,
            "/account/passkeys/",
            new { id = unknownId, newName = "Phone" },
            reauth);
        Assert.Equal(HttpStatusCode.NotFound, renameMiss.StatusCode);

        var renameGarbage = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Patch,
            "/account/passkeys/",
            new { id = "%%%", newName = "Phone" },
            reauth);
        await TestHelpers.AssertValidationErrorAsync(renameGarbage, PasskeyHttp.InvalidCredentialId);

        var deleteOk = await TestHelpers.SendWithCsrfAsync(
            client,
            HttpMethod.Delete,
            $"/account/passkeys/{credentialId}",
            body: null,
            reauth);
        Assert.Equal(HttpStatusCode.OK, deleteOk.StatusCode);

        var listAfter = await client.GetAsync("/account/passkeys/");
        Assert.Equal(HttpStatusCode.OK, listAfter.StatusCode);
        using var listAfterDoc = JsonDocument.Parse(await listAfter.Content.ReadAsStringAsync());
        var passkeysAfter = listAfterDoc.RootElement.TryGetProperty("passkeys", out var after)
            ? after
            : listAfterDoc.RootElement.GetProperty("Passkeys");
        Assert.Equal(0, passkeysAfter.GetArrayLength());
    }

    [Fact]
    public async Task AddPasskey_NameTooLong_ReturnsValidationProblemOnName()
    {
        using var factory = new TestWebApplicationFactory();
        var email = $"pk-namelong-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        var reauth = await TestHelpers.ConfirmIdentityAsync(
            client,
            new { password = TestHelpers.DefaultPassword });

        var add = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/",
            new { credentialJson = "{}", name = new string('a', PasskeyHttp.NameMaxLength + 1) },
            reauth);
        await TestHelpers.AssertValidationErrorAsync(add, "Name");
    }

    [Fact]
    public async Task Login_WithoutRequestOptions_ReturnsInvalidPasskeyState()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var login = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/login",
            new { credentialJson = "{}" });
        await TestHelpers.AssertValidationErrorAsync(login, PasskeyHttp.InvalidPasskeyState);
    }

    [Fact]
    public async Task AddPasskey_WithoutCreationOptions_ReturnsInvalidPasskeyState()
    {
        using var factory = new TestWebApplicationFactory();
        var email = $"pk-nostate-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        var reauth = await TestHelpers.ConfirmIdentityAsync(
            client,
            new { password = TestHelpers.DefaultPassword });

        var add = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/",
            new { credentialJson = "{}" },
            reauth);
        await TestHelpers.AssertValidationErrorAsync(add, PasskeyHttp.InvalidPasskeyState);
    }

    [Fact]
    public async Task Register_WithoutCreationOptions_ReturnsInvalidPasskeyState()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = TestHelpers.CreateClientWithCookies(factory);
        var email = $"pk-reg-nostate-{Guid.NewGuid():N}@test.local";

        var register = await TestHelpers.PostWithCsrfAsync(
            client,
            "/account/passkeys/register",
            new { email, credentialJson = "{}" });
        await TestHelpers.AssertValidationErrorAsync(register, PasskeyHttp.InvalidPasskeyState);
    }
}
