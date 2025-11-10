namespace AuthEndpoints.Identity;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;

public class AntiforgeryEnforcementMiddleware
{
    private readonly RequestDelegate _next;

    public AntiforgeryEnforcementMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var feature = context.Features.Get<IAntiforgeryValidationFeature>();

        if (feature is not null && !feature.IsValid)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid or missing CSRF token.");
            return;
        }

        await _next(context);
    }
}
