using AuthEndpoints.EmailCode;
using AuthEndpoints.Passkey;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.SignIn;

internal sealed class ExplicitEmailCodeSignInCompleterMarker<TUser>
    where TUser : class;

internal sealed class ExplicitPasskeySignInCompleterMarker<TUser>
    where TUser : class;

internal static class LegacySignInCompleters
{
    public static void MarkEmailCode<TUser>(IServiceCollection services)
        where TUser : class
    {
        services.TryAddSingleton<ExplicitEmailCodeSignInCompleterMarker<TUser>>();
    }

    public static void MarkPasskey<TUser>(IServiceCollection services)
        where TUser : class
    {
        services.TryAddSingleton<ExplicitPasskeySignInCompleterMarker<TUser>>();
    }

    public static bool EmailCodeWins<TUser>(IServiceProvider services)
        where TUser : class
    {
        if (services.GetService<ExplicitEmailCodeSignInCompleterMarker<TUser>>() is not null)
        {
            return true;
        }

        using var scope = services.CreateScope();
        var completer = scope.ServiceProvider.GetService<IEmailCodeSignInCompleter<TUser>>();
        return completer is not null && completer is not IdentityEmailCodeSignInCompleter<TUser>;
    }

    public static bool PasskeyWins<TUser>(IServiceProvider services)
        where TUser : class
    {
        if (services.GetService<ExplicitPasskeySignInCompleterMarker<TUser>>() is not null)
        {
            return true;
        }

        using var scope = services.CreateScope();
        var completer = scope.ServiceProvider.GetService<IPasskeySignInCompleter<TUser>>();
        return completer is not null && completer is not IdentityPasskeySignInCompleter<TUser>;
    }

    public static bool EmailCodeWins<TUser>(IServiceProvider services, IEmailCodeSignInCompleter<TUser> completer)
        where TUser : class
    {
        return services.GetService<ExplicitEmailCodeSignInCompleterMarker<TUser>>() is not null
            || completer is not IdentityEmailCodeSignInCompleter<TUser>;
    }

    public static bool PasskeyWins<TUser>(IServiceProvider services, IPasskeySignInCompleter<TUser> completer)
        where TUser : class
    {
        return services.GetService<ExplicitPasskeySignInCompleterMarker<TUser>>() is not null
            || completer is not IdentityPasskeySignInCompleter<TUser>;
    }
}
