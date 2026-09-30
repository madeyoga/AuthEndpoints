using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Installs library ticket and remote-failure handlers after the host delegate.
/// A host <c>OnCreatingTicket</c> assignment cannot remove the library step.
/// </summary>
internal static class OAuthTicketChain
{
    public static void Seal(OAuthEvents events, Func<OAuthCreatingTicketContext, Task> enrich)
    {
        ArgumentNullException.ThrowIfNull(events);
        ArgumentNullException.ThrowIfNull(enrich);

        var hostTicket = events.OnCreatingTicket;
        events.OnCreatingTicket = async context =>
        {
            if (hostTicket is not null)
            {
                await hostTicket(context);
            }

            await enrich(context);
        };

        var hostFailure = events.OnRemoteFailure;
        events.OnRemoteFailure = async context =>
        {
            if (hostFailure is not null)
            {
                await hostFailure(context);
            }

            if (context.Result?.Handled == true || context.Response.HasStarted)
            {
                return;
            }

            await ExternalRemoteFailure.CompleteAsync(context);
        };
    }
}

internal static class ExternalRemoteFailure
{
    public static async Task CompleteAsync(RemoteFailureContext context)
    {
        await context.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        var options = context.HttpContext.RequestServices
            .GetRequiredService<IOptions<ExternalAuthOptions>>()
            .Value;
        var error = context.Request.Query["error"].ToString();
        if (string.IsNullOrEmpty(error))
        {
            error = "access_denied";
        }

        var description = string.IsNullOrEmpty(context.Failure?.Message)
            ? "The external provider denied the request."
            : context.Failure.Message;
        var location = ExternalAuthErrorResults.BrowserLocation(options, error, description);
        context.Response.Redirect(location);
        context.HandleResponse();
    }
}
