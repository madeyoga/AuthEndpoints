using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.MinimalApi;

internal static class WebApplicationExtensions
{
    public static void MapBasicAuthenticationEndpoints(this WebApplication app)
    {
        var definitions = app.Services.GetServices<IEndpointDefinition>();
        var definition = definitions.First(definition => definition.GetType().Name == "");
        definition.MapEndpoints(app);
    }

    public static void MapJwtEndpoints(this WebApplication app)
    {
        var definitions = app.Services.GetServices<IEndpointDefinition>();
        var definition = definitions.First(definition => definition.GetType().Name == "");
        definition.MapEndpoints(app);
    }

    public static void Map2FAEndpoints(this WebApplication app)
    {
        var definitions = app.Services.GetServices<IEndpointDefinition>();
        var definition = definitions.First(definition => definition.GetType().Name == "");
        definition.MapEndpoints(app);
    }

    public static void MapAuthEndpoints(this WebApplication app)
    {
        var definitions = app.Services.GetServices<IEndpointDefinition>();
        foreach(var definition in definitions)
        {
            definition.MapEndpoints(app);
        }
    }
}
