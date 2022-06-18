using Microsoft.AspNetCore.Builder;

namespace AuthEndpoints.MinimalApi;

public interface IEndpointDefinition
{
    void MapEndpoints(WebApplication app);
}
