using System.Reflection;
using AuthEndpoints.External.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.External.OAuth.Tests;

public class LegacyCompleterObsoleteTests
{
    [Fact]
    public void AddCompleter_ReplacesRegistration_AndObsoletePointsAtSignInCompleter()
    {
        var services = new ServiceCollection();
        services.AddExternalAuthEndpoints<OAuthUser>()
            .AddCompleter<ReplacementExternalCompleter>();

        var registered = services.Where(descriptor => descriptor.ServiceType == typeof(IExternalLoginCompleter<OAuthUser>)).ToArray();
        var completer = Assert.Single(registered);
        Assert.Equal(typeof(ReplacementExternalCompleter), completer.ImplementationType);

        AssertObsolete(typeof(IExternalLoginCompleter<>));
        AssertObsolete(typeof(CookieExternalLoginCompleter<>));
        AssertObsolete(typeof(JwtExternalLoginCompleter<>));
        AssertObsolete(typeof(ExternalAuthBuilder).GetMethod(nameof(ExternalAuthBuilder.AddCompleter))!);
    }

    private static void AssertObsolete(MemberInfo member)
    {
        var obsolete = member.GetCustomAttribute<ObsoleteAttribute>();
        Assert.NotNull(obsolete);
        Assert.Contains("ISignInCompleter", obsolete!.Message, StringComparison.Ordinal);
        Assert.Contains("AddSignInCompleter", obsolete.Message, StringComparison.Ordinal);
        Assert.Contains("Removed in 5.0", obsolete.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("o.SignIn.Completer", obsolete.Message, StringComparison.Ordinal);
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
