using Microsoft.AspNetCore.Builder;

namespace AuthEndpoints.Core.Endpoints;

/// <summary>
/// Implements <see cref="IEndpointDefinition"/> to define your endpoint definition.
/// </summary>
public interface IEndpointDefinition
{
    /// <summary>
    /// Use this method to define your minimal api(s).
    /// This method will be called by <see cref="WebApplicationExtensions.MapEndpoints(WebApplication)"/>.
    /// </summary>
    /// <param name="app"></param>
    void MapEndpoints(WebApplication app);
}
