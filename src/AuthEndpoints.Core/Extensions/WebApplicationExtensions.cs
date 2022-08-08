using AuthEndpoints.Core.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Core;

/// <summary>
/// Provides extension to easily map <see cref="IEndpointDefinition"/>
/// </summary>
public static class WebApplicationExtensions
{
    [Obsolete("MapAuthEndpoints is deprecated, please use MapEndpoints instead.", true)]
    public static void MapAuthEndpoints(this WebApplication app)
    {
        var definitions = app.Services.GetServices<IEndpointDefinition>();
        foreach (var definition in definitions)
        {
            definition.MapEndpoints(app);
        }
    }

    public static void MapEndpoints(this WebApplication app)
    {
        var definitions = app.Services.GetServices<IEndpointDefinition>();
        foreach (var definition in definitions)
        {
            definition.MapEndpoints(app);
        }
    }
}
