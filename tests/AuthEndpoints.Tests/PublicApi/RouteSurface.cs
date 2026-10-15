using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests.PublicApi;

internal static class RouteSurface
{
    public static WebApplication Build(Action<WebApplicationBuilder> configure, Action<WebApplication> map)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("routes-" + Guid.NewGuid().ToString("N")));
        configure(builder);

        var app = builder.Build();
        map(app);
        return app;
    }

    public static string Capture(Action<WebApplicationBuilder> configure, Action<WebApplication> map)
    {
        var app = Build(configure, map);

        var auth = app.Services.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
        var lines = new List<string>
        {
            "DefaultScheme: " + Display(auth.DefaultScheme),
            "DefaultAuthenticateScheme: " + Display(auth.DefaultAuthenticateScheme),
            "DefaultChallengeScheme: " + Display(auth.DefaultChallengeScheme),
            "DefaultSignInScheme: " + Display(auth.DefaultSignInScheme),
            "DefaultForbidScheme: " + Display(auth.DefaultForbidScheme),
            "DefaultSignOutScheme: " + Display(auth.DefaultSignOutScheme),
            "Schemes:",
        };
        lines.AddRange(auth.Schemes.Select(scheme => scheme.Name).OrderBy(name => name, StringComparer.Ordinal));
        lines.Add("---");
        lines.AddRange(ListRoutes(app, includeMetadata: true));
        return string.Join('\n', lines) + "\n";
    }

    public static IReadOnlyList<string> ListRoutes(WebApplication app)
    {
        return ListRoutes(app, includeMetadata: false);
    }

    private static IReadOnlyList<string> ListRoutes(WebApplication app, bool includeMetadata)
    {
        return Enumerate(app)
            .Select(endpoint => Format(endpoint, includeMetadata))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(line => line, StringComparer.Ordinal)
            .ToArray();
    }

    private static IEnumerable<Endpoint> Enumerate(WebApplication app)
    {
        return ((IEndpointRouteBuilder)app).DataSources.SelectMany(source => source.Endpoints);
    }

    private static string Format(Endpoint endpoint, bool includeMetadata)
    {
        var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;
        var method = methods is { Count: > 0 }
            ? string.Join(",", methods.OrderBy(name => name, StringComparer.Ordinal))
            : "*";
        var raw = endpoint is RouteEndpoint route
            ? route.RoutePattern.RawText ?? route.RoutePattern.ToString()
            : endpoint.DisplayName ?? "";
        var line = method + " " + raw;
        if (!includeMetadata)
        {
            return line;
        }

        var name = endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName;
        var rateLimit = endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName;
        var antiforgery = endpoint.Metadata.GetOrderedMetadata<IAntiforgeryMetadata>()
                .Any(metadata => metadata.RequiresValidation)
            || endpoint.Metadata.OfType<AuthEndpointsAntiforgeryMetadata>().Any();
        return line
            + " name=" + Display(name)
            + " auth=" + FormatAuth(endpoint)
            + " antiforgery=" + (antiforgery ? "true" : "false")
            + " rateLimit=" + (string.IsNullOrEmpty(rateLimit) ? "(none)" : rateLimit);
    }

    private static string FormatAuth(Endpoint endpoint)
    {
        var authorize = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>();
        if (authorize.Count == 0)
        {
            return "(none)";
        }

        return string.Join(
            ";",
            authorize.Select(item => string.IsNullOrEmpty(item.AuthenticationSchemes) ? "(default)" : item.AuthenticationSchemes));
    }

    private static string Display(string? value) => string.IsNullOrEmpty(value) ? "(none)" : value;
}
