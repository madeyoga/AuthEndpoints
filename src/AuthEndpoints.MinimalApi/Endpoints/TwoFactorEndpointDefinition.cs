using AuthEndpoints.MinimalApi.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.MinimalApi.EndpointDefinitions;
public class TwoFactorEndpointDefinition<TKey, TUser> : IEndpointDefinition
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    public void MapEndpoints(WebApplication app)
    {
    }
}
