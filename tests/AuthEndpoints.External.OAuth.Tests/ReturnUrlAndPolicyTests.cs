using System.Text.Json;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.External.OAuth.GitHub;
using AuthEndpoints.External.OAuth.Google;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth.Tests;

public class ReturnUrlAndPolicyTests
{
    [Theory]
    [InlineData("/")]
    [InlineData("/dashboard")]
    [InlineData("/auth/external/error")]
    public void Rooted_paths_are_local_on_linux(string url)
    {
        Assert.True(ExternalAuthReturnUrl.IsRelativeLocalUrl(url));
        Assert.Equal(url, ExternalAuthReturnUrl.Resolve(url, "/", []));
    }

    [Theory]
    [InlineData("//evil.example/x")]
    [InlineData("/\\evil")]
    [InlineData("~/dashboard")]
    [InlineData("~//evil.example")]
    [InlineData("~/ok\t")]
    [InlineData("/dash%0d%0aLocation:https://evil")]
    [InlineData("https://evil.example/x")]
    public void Unsafe_return_urls_fall_back(string url)
    {
        Assert.False(ExternalAuthReturnUrl.IsRelativeLocalUrl(url));
        Assert.Equal("/", ExternalAuthReturnUrl.Resolve(url, "/", ["https://app.example.com"]));
    }

    [Fact]
    public void Absolute_return_matches_scheme_host_and_port()
    {
        var allowed = new[] { "https://app.example.com" };
        Assert.Equal(
            "https://app.example.com/done",
            ExternalAuthReturnUrl.Resolve("https://app.example.com/done", "/", allowed));
        Assert.Equal(
            "/",
            ExternalAuthReturnUrl.Resolve("https://app.example.com:444/done", "/", allowed));
        Assert.Equal(
            "/",
            ExternalAuthReturnUrl.Resolve("http://app.example.com/done", "/", allowed));
    }

    [Fact]
    public void Default_options_pass_startup_validation()
    {
        var result = new ExternalAuthOptionsValidator().Validate(null, new ExternalAuthOptions());
        Assert.True(result.Succeeded);
        Assert.False(new ExternalAuthOptions().AutoLinkByEmail);
    }

    [Fact]
    public void Origin_entries_reject_paths_and_userinfo()
    {
        Assert.True(ExternalAuthReturnUrl.IsAllowedOriginEntry("https://app.example.com"));
        Assert.True(ExternalAuthReturnUrl.IsAllowedOriginEntry("https://app.example.com/"));
        Assert.False(ExternalAuthReturnUrl.IsAllowedOriginEntry("https://app.example.com/app"));
        Assert.False(ExternalAuthReturnUrl.IsAllowedOriginEntry("https://user:pass@app.example.com"));
    }

    [Fact]
    public void Auto_link_requires_verified_provider_email_and_confirmed_local_email()
    {
        var denied = ExternalEmailPolicy.Decide(
            "GitHub",
            "GitHub",
            hasExistingLogin: false,
            new ExternalEmailFacts("a@example.com", Verified: true, LocalEmailConfirmed: false),
            hasLocalUser: true,
            requireVerifiedEmail: true,
            autoLinkByEmail: true);
        Assert.Equal("email_unconfirmed", denied.Error);

        var unverified = ExternalEmailPolicy.Decide(
            "GitHub",
            "GitHub",
            false,
            new ExternalEmailFacts("a@example.com", false, true),
            true,
            requireVerifiedEmail: false,
            autoLinkByEmail: true);
        Assert.Equal("email_unverified", unverified.Error);

        var linked = ExternalEmailPolicy.Decide(
            "GitHub",
            "GitHub",
            false,
            new ExternalEmailFacts("a@example.com", true, true),
            true,
            true,
            true);
        Assert.Equal(ExternalProvisionKind.LinkExistingUser, linked.Kind);

        var off = ExternalEmailPolicy.Decide(
            "GitHub",
            "GitHub",
            false,
            new ExternalEmailFacts("a@example.com", true, true),
            true,
            true,
            autoLinkByEmail: false);
        Assert.Equal("auto_link_disabled", off.Error);
    }

    [Fact]
    public void Provider_mismatch_is_denied_before_email_rules()
    {
        var decision = ExternalEmailPolicy.Decide(
            "Google",
            "GitHub",
            hasExistingLogin: true,
            new ExternalEmailFacts("a@example.com", true, true),
            false,
            true,
            false);
        Assert.Equal("provider_mismatch", decision.Error);
    }

    [Theory]
    [InlineData(false, 0, 1, false)]
    [InlineData(true, 0, 1, true)]
    [InlineData(false, 1, 1, true)]
    [InlineData(false, 0, 2, true)]
    public void Unlink_keeps_a_remaining_sign_in_method(bool password, int passkeys, int logins, bool allowed)
    {
        Assert.Equal(allowed, ExternalLoginUnlinkPolicy.CanRemove(password, passkeys, logins));
    }

    [Fact]
    public void Core_assembly_does_not_reference_provider_handlers()
    {
        var names = typeof(ExternalAuthOptions).Assembly.GetReferencedAssemblies().Select(a => a.Name).ToArray();
        Assert.DoesNotContain("AspNet.Security.OAuth.GitHub", names);
        Assert.DoesNotContain("Microsoft.AspNetCore.Authentication.Google", names);
    }

    [Fact]
    public void GitHub_selects_verified_primary_else_any_verified()
    {
        using var primary = JsonDocument.Parse("""
            [
              {"email":"unverified@example.com","primary":true,"verified":false},
              {"email":"other@example.com","primary":false,"verified":true}
            ]
            """);
        Assert.Equal("other@example.com", GitHubUserEmails.SelectVerified(primary.RootElement));

        using var verifiedPrimary = JsonDocument.Parse("""
            [
              {"email":"second@example.com","primary":false,"verified":true},
              {"email":"first@example.com","primary":true,"verified":true}
            ]
            """);
        Assert.Equal("first@example.com", GitHubUserEmails.SelectVerified(verifiedPrimary.RootElement));
    }

    [Fact]
    public async Task GitHub_apply_drops_unverified_profile_email()
    {
        var identity = new System.Security.Claims.ClaimsIdentity();
        identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, "public@example.com"));
        identity.AddClaim(new System.Security.Claims.Claim("email_verified", "true"));

        var handler = new StubHandler("""[{"email":"public@example.com","primary":true,"verified":false}]""");
        await GitHubUserEmails.ApplyAsync(identity, new HttpClient(handler), "token", CancellationToken.None);

        Assert.Null(ExternalEmailClaims.GetEmail(new System.Security.Claims.ClaimsPrincipal(identity)));
        Assert.False(ExternalEmailClaims.IsEmailVerified(new System.Security.Claims.ClaimsPrincipal(identity)));
    }

    [Fact]
    public void Google_verified_flag_follows_userinfo_not_a_host_stamp()
    {
        var identity = new System.Security.Claims.ClaimsIdentity();
        identity.AddClaim(new System.Security.Claims.Claim("email_verified", "true"));
        using var user = JsonDocument.Parse("""{"email":"a@example.com","email_verified":false}""");
        GoogleEmailProof.Apply(identity, user.RootElement);
        Assert.False(ExternalEmailClaims.IsEmailVerified(new System.Security.Claims.ClaimsPrincipal(identity)));

        using var verified = JsonDocument.Parse("""{"email":"a@example.com","email_verified":true}""");
        GoogleEmailProof.Apply(identity, verified.RootElement);
        Assert.True(ExternalEmailClaims.IsEmailVerified(new System.Security.Claims.ClaimsPrincipal(identity)));
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly string _body;

        public StubHandler(string body) => _body = body;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("https://api.github.com/user/emails", request.RequestUri?.ToString());
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(_body, System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }
}
