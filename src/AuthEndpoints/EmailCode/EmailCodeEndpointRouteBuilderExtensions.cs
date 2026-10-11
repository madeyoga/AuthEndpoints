using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.EmailCode;

public static class EmailCodeEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>POST /emailCode/send</c> and <c>POST /emailCode/verify</c>.
    /// Send uses <see cref="AuthEndpointsConstants.EmailCodeSendPolicy"/>.
    /// Verify uses <see cref="AuthEndpointsConstants.LoginPolicy"/>.
    /// Neither route requires antiforgery.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var group = endpoints.MapGroup("");
        group.MapPost("/emailCode/send", EmailCodeEndpoints<TUser>.Send)
            .RequireRateLimiting(AuthEndpointsConstants.EmailCodeSendPolicy);
        group.MapPost("/emailCode/verify", EmailCodeEndpoints<TUser>.Verify)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);
        return group;
    }
}
