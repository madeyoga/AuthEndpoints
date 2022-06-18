using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.MinimalApi;

public static class WebApplicationExtensions
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        var definitions = app.Services.GetServices<IEndpointDefinition>();
        foreach (var definition in definitions)
        {
            definition.MapEndpoints(app);
        }
    }
}
