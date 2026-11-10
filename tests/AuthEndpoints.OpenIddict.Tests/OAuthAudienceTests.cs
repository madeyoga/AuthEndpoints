using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary><see cref="OAuthServerOptions.AcceptedAudiences"/>: one host that serves more than one resource.</summary>
public sealed class OAuthAudienceTests
{
    private const string ThirdResource = "https://third.example/api";

    [Fact]
    public async Task By_default_a_token_for_an_additional_resource_is_rejected_by_this_host()
    {
        await using var host = await StartMultiAsync(accept: false);
        var (user, _) = await host.UserAsync("aud-default");
        var (_, other) = await host.IssueAsync(user, resource: OtherResource);

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(other.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(host, "/other/me", other.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task An_accepted_audience_is_accepted_and_each_route_checks_its_own_audience()
    {
        await using var host = await StartMultiAsync(accept: true);
        var (user, userId) = await host.UserAsync("aud-accepted");
        var (_, other) = await host.IssueAsync(user, resource: OtherResource, name: "Other");
        var (_, main) = await host.IssueAsync(user, name: "Main");

        // Validation accepts both audiences: a policy that only requires an authenticated user lets both through.
        Assert.Equal(userId, await host.SubjectAsync(other.AccessToken));
        Assert.Equal(userId, await host.SubjectAsync(main.AccessToken));

        // RequireOAuthAudience keeps each token on its own resource.
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/other/me", other.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, "/main/me", other.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/main/me", main.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, "/other/me", main.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(host, "/other/me", null)).StatusCode);
    }

    [Fact]
    public async Task A_configured_resource_that_is_not_accepted_is_still_rejected()
    {
        await using var host = await StartMultiAsync(accept: true);
        var (user, _) = await host.UserAsync("aud-third");
        var (_, third) = await host.IssueAsync(user, resource: ThirdResource);

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(third.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(host, "/other/me", third.AccessToken)).StatusCode);
    }

    [Theory]
    [InlineData("https://unknown.example/api")]
    [InlineData("https://localhost/api/")]
    public void Accepted_audiences_must_be_configured_resources(string audience)
    {
        var options = Valid();
        options.AcceptedAudiences.Add(audience);
        var result = new OAuthServerOptionsValidator().Validate(null, options);
        Assert.True(result.Failed);
        Assert.Contains($"AcceptedAudiences entry '{audience}'", string.Join('\n', result.Failures!), StringComparison.Ordinal);
    }

    [Fact]
    public void Accepted_audiences_may_list_the_audience_and_additional_resources()
    {
        var options = Valid();
        options.AcceptedAudiences.Add(OtherResource);
        options.AcceptedAudiences.Add(Audience);
        Assert.True(new OAuthServerOptionsValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public async Task An_unconfigured_accepted_audience_stops_startup()
    {
        await Assert.ThrowsAsync<Microsoft.Extensions.Options.OptionsValidationException>(
            () => StartAsync(options => options.AcceptedAudiences.Add(ThirdResource)));
    }

    private static Task<OAuthTestHost> StartMultiAsync(bool accept) => StartAsync(
        options =>
        {
            options.AdditionalResources.Add(ThirdResource);
            if (accept)
            {
                options.AcceptedAudiences.Add(OtherResource);
            }
        },
        services: services => services.Configure<AuthorizationOptions>(options =>
        {
            options.AddPolicy("main", policy => policy.RequireOAuthAudience(Audience));
            options.AddPolicy("other", policy => policy.RequireOAuthAudience(OtherResource));
        }),
        map: app =>
        {
            app.MapGet("/main/me", () => Results.Ok()).RequireAuthorization("main");
            app.MapGet("/other/me", () => Results.Ok()).RequireAuthorization("other");
        });

    private static async Task<HttpResponseMessage> CallAsync(OAuthTestHost host, string path, string? accessToken)
    {
        using var api = host.Client(cookies: false);
        if (accessToken is not null)
        {
            api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        return await api.GetAsync(path);
    }

    private static OAuthServerOptions Valid()
    {
        var options = new OAuthServerOptions
        {
            Issuer = new Uri(Issuer),
            Audience = Audience,
            LoginUrl = LoginUrl,
            ConsentUrl = ConsentUrl,
        };
        options.AdditionalResources.Add(OtherResource);
        options.Certificates.UseEphemeralKeys = true;
        return options;
    }
}
