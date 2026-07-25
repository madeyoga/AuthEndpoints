using Microsoft.AspNetCore.Builder;

namespace AuthEndpoints;

public static class AuthEndpointsApplicationBuilderExtensions
{
    private const string PipelineMarkerKey = "__AuthEndpoints.Pipeline";

    /// <summary>
    /// Adds the AuthEndpoints middleware pipeline in the required order:
    /// authentication, authorization, rate limiting, antiforgery.
    /// Call after exception-handling middleware. Hosts should enable HTTPS in Production separately.
    /// Safe to call once; a second call is a no-op.
    /// </summary>
    public static IApplicationBuilder UseAuthEndpoints(this IApplicationBuilder app)
    {
        if (app.Properties.ContainsKey(PipelineMarkerKey))
        {
            return app;
        }

        app.Properties[PipelineMarkerKey] = true;

        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();
        app.UseAntiforgery();

        return app;
    }
}
