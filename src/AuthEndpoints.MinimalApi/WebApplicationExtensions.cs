using AuthEndpoints.MinimalApi.EndpointDefinitions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.MinimalApi;

internal static class WebApplicationExtensions
{
    public static void MapBasicAuthenticationEndpoints(this WebApplication app)
    {
        var definition = app.Services.GetRequiredService<BasicAuthEndpointDefinition>();
        definition.MapEndpoints(app);
    }

    public static void MapJwtEndpoints(this WebApplication app)
    {
        var definition = app.Services.GetRequiredService<JwtEndpointDefinition>();
        definition.MapEndpoints(app);
    }

    public static void Map2FAEndpoints(this WebApplication app)
    {
        var definition = app.Services.GetRequiredService<TwoFactorEndpointDefinition>();
        definition.MapEndpoints(app);
    }
}
