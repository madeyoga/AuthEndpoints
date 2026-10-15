using AuthEndpoints.External.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.External.OAuth.Tests;

public class LegacyCompleterObsoleteTests
{
    [Fact]
    public void AddCompleter_ReplacesTheRegisteredCompleter()
    {
        var services = new ServiceCollection();
        services.AddExternalAuthEndpoints<OAuthUser>()
            .AddCompleter<ReplacementExternalCompleter>();

        var registered = services.Where(descriptor => descriptor.ServiceType == typeof(IExternalLoginCompleter<OAuthUser>)).ToArray();
        var completer = Assert.Single(registered);
        Assert.Equal(typeof(ReplacementExternalCompleter), completer.ImplementationType);
    }

    private sealed class ReplacementExternalCompleter : IExternalLoginCompleter<OAuthUser>
    {
        public Task<IResult> CompleteAsync(
            HttpContext httpContext,
            OAuthUser user,
            ExternalLoginInfo info,
            string? returnUrl,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IResult>(Results.Ok());
    }
}
