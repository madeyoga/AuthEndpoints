using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.Identity;

/// <summary>
/// Returns 404 for <c>POST /manage/password</c> when password sign-in is not mapped.
/// Every other endpoint uses the framework result handler.
/// </summary>
internal sealed class SetPasswordAvailabilityResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly IAuthorizationMiddlewareResultHandler _inner;

    public SetPasswordAvailabilityResultHandler(IAuthorizationMiddlewareResultHandler inner)
    {
        _inner = inner;
    }

    public Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        var endpoint = context.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<SetPasswordEndpointMetadata>() is not null
            && !PasswordSignInMap.IsMapped(context.RequestServices))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return Task.CompletedTask;
        }

        return _inner.HandleAsync(next, context, policy, authorizeResult);
    }
}
