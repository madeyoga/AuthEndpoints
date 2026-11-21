using System.Net;
using System.Security.Claims;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

/// <summary>The caller kind (<c>ae:caller</c>), <c>act</c>, and <c>RequireDirectPerson</c> in the core package.</summary>
public class CallerKindTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public CallerKindTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Theory]
    [InlineData("Identity.Application")] // application cookie, and Identity bearer tokens (same identity type)
    [InlineData("AuthenticationTypes.Federation")] // AuthEndpoints JWT
    public void Built_in_sign_in_identities_are_people(string authenticationType)
    {
        var principal = Principal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "u1")], authenticationType));
        Assert.Equal(CallerKinds.Person, principal.GetCallerKind());
        Assert.True(principal.IsDirectPerson());
        Assert.Null(principal.GetActingClientId());
    }

    [Fact]
    public void The_claim_wins_and_unknown_identities_are_not_people()
    {
        var delegated = Principal(new ClaimsIdentity(
            [
                new Claim(CallerKinds.ClaimType, CallerKinds.Delegated),
                new Claim(CallerKinds.ActorClaimType, """{"client_id":"assistant"}"""),
            ],
            "OpenIddict.Validation.AspNetCore"));
        Assert.Equal(CallerKinds.Delegated, delegated.GetCallerKind());
        Assert.False(delegated.IsDirectPerson());
        Assert.Equal("assistant", delegated.GetActingClientId());

        // A host scheme that sets no kind is unknown, and RequireDirectPerson refuses it.
        var unknown = Principal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "u1")], "Cookies"));
        Assert.Null(unknown.GetCallerKind());
        Assert.False(unknown.IsDirectPerson());

        // A host scheme can say it is a person.
        var hostPerson = Principal(new ClaimsIdentity([new Claim(CallerKinds.ClaimType, CallerKinds.Person)], "Cookies"));
        Assert.True(hostPerson.IsDirectPerson());

        // A built-in identity that a host tagged otherwise keeps the host's kind.
        var tagged = Principal(new ClaimsIdentity([new Claim(CallerKinds.ClaimType, "service")], IdentityConstants.ApplicationScheme));
        Assert.Equal("service", tagged.GetCallerKind());
        Assert.False(tagged.IsDirectPerson());
    }

    [Fact]
    public void A_cookie_next_to_a_delegated_token_does_not_make_it_a_person()
    {
        var principal = new ClaimsPrincipal(
        [
            new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "u1")], IdentityConstants.ApplicationScheme),
            new ClaimsIdentity([new Claim(CallerKinds.ClaimType, CallerKinds.Delegated)], "OpenIddict.Validation.AspNetCore"),
        ]);
        Assert.Equal(CallerKinds.Delegated, principal.GetCallerKind());
        Assert.False(principal.IsDirectPerson());
    }

    [Fact]
    public void Anonymous_and_malformed_act_values_are_handled()
    {
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
        Assert.Null(anonymous.GetCallerKind());
        Assert.False(anonymous.IsDirectPerson());

        var malformed = Principal(new ClaimsIdentity([new Claim(CallerKinds.ActorClaimType, "not json")], "x"));
        Assert.Null(malformed.GetActingClientId());
    }

    [Fact]
    public async Task The_policy_refuses_a_delegated_caller()
    {
        var services = new ServiceCollection().AddLogging().AddAuthorization().BuildServiceProvider();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var policy = new AuthorizationPolicyBuilder().RequireDirectPerson().Build();

        var person = Principal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "u1")], IdentityConstants.ApplicationScheme));
        var delegated = Principal(new ClaimsIdentity([new Claim(CallerKinds.ClaimType, CallerKinds.Delegated)], "OAuth"));
        var apiKey = Principal(new ClaimsIdentity([new Claim(CallerKinds.ClaimType, CallerKinds.ApiKey)], "ApiKey"));

        Assert.True((await authorization.AuthorizeAsync(person, null, policy)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(delegated, null, policy)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(apiKey, null, policy)).Succeeded);
    }

    [Theory]
    [InlineData("POST /identity/manage/info")]
    [InlineData("POST /identity/manage/2fa")]
    [InlineData("POST /identity/confirmIdentity")]
    [InlineData("POST /account/passkeys/")]
    [InlineData("DELETE /account/passkeys/{credentialIdUrl}")]
    [InlineData("GET /identity/manage/info")]
    public void Sensitive_built_in_routes_require_a_direct_person(string route)
    {
        var parts = route.Split(' ', 2);
        var endpoint = _factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(item => "/" + item.RoutePattern.RawText!.TrimStart('/') == parts[1]
                && item.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.HttpMethodMetadata>()?.HttpMethods.Contains(parts[0]) == true);
        Assert.Contains(
            endpoint.Metadata.OfType<AuthorizationPolicy>().SelectMany(policy => policy.Requirements),
            requirement => requirement is DirectPersonRequirement);
    }

    [Fact]
    public async Task A_cookie_whose_principal_a_host_tagged_as_not_a_person_gets_403_on_management_routes()
    {
        await using var factory = _factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.Replace(ServiceDescriptor.Scoped<IUserClaimsPrincipalFactory<TestAppUser>, ServiceTaggingFactory>())));

        var robot = $"robot-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, robot);
        using var robotClient = TestHelpers.CreateClientWithCookies(factory);
        await TestHelpers.LoginCookieAsync(robotClient, robot, TestHelpers.DefaultPassword);
        Assert.Equal(HttpStatusCode.Forbidden, (await robotClient.GetAsync("/identity/manage/info")).StatusCode);

        var person = $"person-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, person);
        using var personClient = TestHelpers.CreateClientWithCookies(factory);
        await TestHelpers.LoginCookieAsync(personClient, person, TestHelpers.DefaultPassword);
        Assert.Equal(HttpStatusCode.OK, (await personClient.GetAsync("/identity/manage/info")).StatusCode);
    }

    private static ClaimsPrincipal Principal(ClaimsIdentity identity) => new(identity);

    /// <summary>A host principal hook that marks some accounts as a service, not a person.</summary>
    private sealed class ServiceTaggingFactory(UserManager<TestAppUser> users, IOptions<IdentityOptions> options)
        : UserClaimsPrincipalFactory<TestAppUser>(users, options)
    {
        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(TestAppUser user)
        {
            var identity = await base.GenerateClaimsAsync(user);
            if (user.Email?.StartsWith("robot-", StringComparison.Ordinal) == true)
            {
                identity.AddClaim(new Claim(CallerKinds.ClaimType, "service"));
            }

            return identity;
        }
    }
}
