using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

internal static class ExternalSignInRedirect
{
    public static string Url(HttpContext httpContext, string? returnUrl)
    {
        var options = httpContext.RequestServices.GetService<IOptions<ExternalAuthOptions>>()?.Value
            ?? new ExternalAuthOptions();
        return ExternalAuthReturnUrl.Resolve(
            returnUrl,
            options.DefaultReturnUrl,
            options.AllowedReturnUrlOrigins.ToList());
    }
}