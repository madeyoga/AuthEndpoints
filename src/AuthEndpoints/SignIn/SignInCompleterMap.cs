using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.SignIn;

internal static class SignInCompleterMap
{
    public static string FromSession(AuthEndpointsSession session)
    {
        return session switch
        {
            AuthEndpointsSession.Cookie => SignInCompleters.Cookie,
            AuthEndpointsSession.IdentityBearer => SignInCompleters.IdentityBearer,
            AuthEndpointsSession.Jwt => SignInCompleters.Jwt,
            _ => throw new ArgumentOutOfRangeException(nameof(session), session, "Unknown sign-in session."),
        };
    }

    public static void EnsureSelected<TUser>(IEndpointRouteBuilder endpoints, string name, string mapMethod)
        where TUser : class
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (string.Equals(name, SignInCompleters.Jwt, StringComparison.Ordinal))
        {
            AuthEndpointsModules.WarnIfMissing<JwtEndpointsModule>(endpoints, "AddJwtEndpoints", mapMethod);
            if (!AuthEndpointsModules.IsRegistered<JwtEndpointsModule>(endpoints.ServiceProvider))
            {
                return;
            }
        }

        if (!SignInCompleterRegistry.Contains<TUser>(endpoints.ServiceProvider, name))
        {
            throw new InvalidOperationException(MissingMessage<TUser>(name));
        }
    }

    /// <summary>
    /// When the map passed no name, validate <see cref="SignInCompletionOptions.Default"/> if it will be used.
    /// A 3.x legacy completer wins over that default, so a missing keyed service is not an error in that case.
    /// The name must be registered for <typeparamref name="TUser"/> or as an open generic.
    /// </summary>
    public static void EnsureConfiguredDefault<TUser>(IEndpointRouteBuilder endpoints, string mapMethod, bool legacyWins)
        where TUser : class
    {
        if (legacyWins)
        {
            return;
        }

        var configured = endpoints.ServiceProvider.GetService<IOptions<SignInCompletionOptions>>()?.Value.Default;
        if (string.IsNullOrWhiteSpace(configured))
        {
            return;
        }

        if (string.Equals(configured, SignInCompleters.Jwt, StringComparison.Ordinal))
        {
            AuthEndpointsModules.WarnIfMissing<JwtEndpointsModule>(endpoints, "AddJwtEndpoints", mapMethod);
            if (!AuthEndpointsModules.IsRegistered<JwtEndpointsModule>(endpoints.ServiceProvider))
            {
                return;
            }
        }

        if (!SignInCompleterRegistry.Contains<TUser>(endpoints.ServiceProvider, configured))
        {
            throw new InvalidOperationException(MissingMessage<TUser>(configured));
        }
    }

    private static string MissingMessage<TUser>(string name)
        => $"No ISignInCompleter<{typeof(TUser).Name}> named '{name}' is registered (AddSignInCompleter).";
}
