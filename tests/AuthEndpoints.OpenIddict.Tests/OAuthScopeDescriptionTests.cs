using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>Scope display names and descriptions on the consent card (#448).</summary>
public sealed class OAuthScopeDescriptionTests
{
    [Fact]
    public async Task The_card_keeps_scope_names_and_adds_details_in_the_request_culture()
    {
        await using var host = await StartAsync(Describe, map: Localize);
        var (user, _) = await host.UserAsync("scopes");
        var client = await host.RegisterAsync();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "api profile");

        var card = await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}");

        // scopes is unchanged: names, in the granted order.
        Assert.Equal(["api", "profile", "offline_access"], card.GetProperty("scopes").EnumerateArray().Select(item => item.GetString()!).ToArray());
        var details = Details(card);
        Assert.Equal(["api", "profile", "offline_access"], details.Select(detail => detail.Name).ToArray());
        Assert.Equal(new Detail("api", "Use the API", "Read and change your data through the API."), details[0]);
        // No definition: the name, and no description.
        Assert.Equal(new Detail("profile", "profile", null), details[1]);
        Assert.Equal(new Detail("offline_access", "Stay connected", null), details[2]);

        Assert.Equal(
            new Detail("api", "Utiliser l'API", "Lire et modifier vos données."),
            Details(await CardAsync(user, id, "fr-FR"))[0]);
        // pt-BR has its own display name, and falls back to pt for the description.
        Assert.Equal(
            new Detail("api", "Usar a API (Brasil)", "Ler e alterar seus dados."),
            Details(await CardAsync(user, id, "pt-BR"))[0]);
        // A culture with no text gets the default.
        Assert.Equal(
            new Detail("api", "Use the API", "Read and change your data through the API."),
            Details(await CardAsync(user, id, "de"))[0]);
    }

    [Fact]
    public async Task Without_definitions_every_scope_is_shown_by_its_name()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("plain");
        var client = await host.RegisterAsync();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        var details = Details(await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}"));
        Assert.Equal([new Detail("api", "api", null), new Detail("offline_access", "offline_access", null)], details);
    }

    [Fact]
    public async Task The_consent_service_and_principal_factory_see_the_details()
    {
        OAuthPendingRequest? seen = null;
        await using var host = await StartAsync(Describe, map: app =>
        {
            Localize(app);
            app.MapPost("/test/approve-with-details/{id:guid}", async (Guid id, HttpContext http, IOAuthConsentService consent) =>
            {
                var userId = http.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)!.Value;
                var result = await consent.ApproveAsync(id, userId, context =>
                {
                    seen = context.Request;
                    return ValueTask.FromResult<System.Security.Claims.ClaimsPrincipal?>(OAuthPrincipals.ForSubject(userId));
                });
                return Results.Ok(result.Status.ToString());
            }).DisableAntiforgery();
        });
        var (user, _) = await host.UserAsync("service");
        var client = await host.RegisterAsync();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        using var request = new HttpRequestMessage(HttpMethod.Post, $"/test/approve-with-details/{id}");
        request.Headers.AcceptLanguage.ParseAdd("fr");
        var response = await user.SendAsync(request);
        Assert.Equal("\"Approved\"", await response.Content.ReadAsStringAsync());
        Assert.NotNull(seen);
        Assert.Equal("Utiliser l'API", seen!.ScopeDetails[0].DisplayName);
    }

    [Fact]
    public async Task An_app_can_replace_where_the_descriptions_come_from()
    {
        await using var host = await StartAsync(Describe, map: Localize, server: builder => builder.AddScopeDescriptions<UpperCaseDescriptions>());
        var (user, _) = await host.UserAsync("custom");
        var client = await host.RegisterAsync();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        var details = Details(await CardAsync(user, id, "fr"));
        Assert.Equal([new Detail("api", "API", "fr"), new Detail("offline_access", "OFFLINE_ACCESS", "fr")], details);
    }

    [Fact]
    public async Task A_service_registered_before_the_server_is_kept()
    {
        await using var host = await StartAsync(beforeServer: services => services.AddScoped<IOAuthScopeDescriptions, UpperCaseDescriptions>());
        var (user, _) = await host.UserAsync("before");
        var client = await host.RegisterAsync();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        Assert.Equal("API", Details(await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}"))[0].DisplayName);
    }

    /// <summary>Stands in for a database or resource-file source.</summary>
    private sealed class UpperCaseDescriptions : IOAuthScopeDescriptions
    {
        public ValueTask<IReadOnlyList<OAuthScopeDetail>> DescribeAsync(
            IReadOnlyList<string> scopes, CultureInfo culture, CancellationToken cancellationToken)
            => ValueTask.FromResult<IReadOnlyList<OAuthScopeDetail>>(
                scopes.Select(scope => new OAuthScopeDetail(scope, scope.ToUpperInvariant(), culture.TwoLetterISOLanguageName)).ToList());
    }

    [Fact]
    public void Definitions_bind_from_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["OAuthServer:Scopes:0"] = "reports.read",
            ["OAuthServer:ScopeDefinitions:0:Name"] = "reports.read",
            ["OAuthServer:ScopeDefinitions:0:DisplayName"] = "Read your reports",
            ["OAuthServer:ScopeDefinitions:0:Description"] = "See reports you can open.",
            ["OAuthServer:ScopeDefinitions:0:DisplayNames:fr"] = "Lire vos rapports",
            ["OAuthServer:ScopeDefinitions:0:Descriptions:fr"] = "Voir les rapports.",
        }).Build();
        var options = new OAuthServerOptions();
        configuration.GetSection("OAuthServer").Bind(options);

        var definition = Assert.Single(options.ScopeDefinitions);
        Assert.Equal("reports.read", definition.Name);
        Assert.Equal("Lire vos rapports", definition.DisplayNames["FR"]);
        var detail = OAuthScopeDescriptions.Describe(["reports.read"], options.ScopeDefinitions, CultureInfo.GetCultureInfo("fr-CA"));
        Assert.Equal(new OAuthScopeDetail("reports.read", "Lire vos rapports", "Voir les rapports."), detail[0]);
    }

    [Fact]
    public void Invalid_definitions_fail_validation()
    {
        var options = new OAuthServerOptions
        {
            Issuer = new Uri(Issuer),
            Audience = Audience,
            LoginUrl = LoginUrl,
            ConsentUrl = ConsentUrl,
        };
        options.Certificates.UseEphemeralKeys = true;
        options.Scopes.Add("api");
        options.ScopeDefinitions.Add(new OAuthScopeDefinition { Name = "api" });
        options.ScopeDefinitions.Add(new OAuthScopeDefinition { Name = "api" });
        options.ScopeDefinitions.Add(new OAuthScopeDefinition { Name = "unknown" });
        options.ScopeDefinitions.Add(new OAuthScopeDefinition());
        var bad = new OAuthScopeDefinition { Name = "offline_access" };
        bad.DisplayNames["not-a-culture-xx-yy"] = "?";
        options.ScopeDefinitions.Add(bad);

        var failures = new OAuthServerOptionsValidator().Validate(null, options).Failures!.ToList();
        Assert.Contains(failures, failure => failure.Contains("lists 'api' twice", StringComparison.Ordinal));
        Assert.Contains(failures, failure => failure.Contains("'unknown' is not in", StringComparison.Ordinal));
        Assert.Contains(failures, failure => failure.Contains("needs a Name", StringComparison.Ordinal));
        Assert.Contains(failures, failure => failure.Contains("'not-a-culture-xx-yy'", StringComparison.Ordinal));
        Assert.DoesNotContain(failures, failure => failure.Contains("'offline_access' is not in", StringComparison.Ordinal));
    }

    private static void Describe(OAuthServerOptions options)
    {
        var api = new OAuthScopeDefinition
        {
            Name = "api",
            DisplayName = "Use the API",
            Description = "Read and change your data through the API.",
        };
        api.DisplayNames["fr"] = "Utiliser l'API";
        api.Descriptions["fr"] = "Lire et modifier vos données.";
        api.DisplayNames["pt"] = "Usar a API";
        api.DisplayNames["pt-BR"] = "Usar a API (Brasil)";
        api.Descriptions["pt"] = "Ler e alterar seus dados.";
        options.ScopeDefinitions.Add(api);
        options.ScopeDefinitions.Add(new OAuthScopeDefinition { Name = "offline_access", DisplayName = "Stay connected" });
    }

    private static void Localize(WebApplication app)
        => app.UseRequestLocalization(options =>
        {
            string[] cultures = ["en", "fr", "fr-FR", "pt", "pt-BR", "de"];
            options.SetDefaultCulture("en").AddSupportedCultures(cultures).AddSupportedUICultures(cultures);
        });

    private static async Task<JsonElement> CardAsync(HttpClient user, Guid id, string culture)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/oauth/requests/{id}");
        request.Headers.AcceptLanguage.ParseAdd(culture);
        var response = await user.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private static Detail[] Details(JsonElement card)
        => card.GetProperty("scopeDetails").EnumerateArray()
            .Select(item => new Detail(
                item.GetProperty("name").GetString()!,
                item.GetProperty("displayName").GetString()!,
                item.GetProperty("description").GetString()))
            .ToArray();

    private sealed record Detail(string Name, string DisplayName, string? Description);
}
