using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests.PublicApi;

internal static class RouteSurface
{
    public static string Capture(Action<WebApplicationBuilder> configure, Action<WebApplication> map)
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
        lines.AddRange(ListRoutes(app));
        return string.Join('\n', lines) + "\n";
    }

    public static IReadOnlyList<string> ListRoutes(WebApplication app)
    {
        return ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .Select(Format)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(line => line, StringComparer.Ordinal)
            .ToArray();
    }

    private static string Format(Endpoint endpoint)
    {
        var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;
        var method = methods is { Count: > 0 }
            ? string.Join(",", methods.OrderBy(name => name, StringComparer.Ordinal))
            : "*";
        var raw = endpoint is RouteEndpoint route
            ? route.RoutePattern.RawText ?? route.RoutePattern.ToString()
            : endpoint.DisplayName ?? "";
        return method + " " + raw;
    }

    private static string Display(string? value) => string.IsNullOrEmpty(value) ? "(none)" : value;
}
