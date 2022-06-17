using Microsoft.AspNetCore.Builder;

namespace AuthEndpoints.MinimalApi.Endpoints;

public interface IEndpointDefinition
{
    void MapEndpoints(WebApplication app);
}
