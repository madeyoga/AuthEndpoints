using AuthEndpoints.SignIn;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

public static class PasswordServiceCollectionExtensions
{
    /// <summary>
    /// Registers the login and account-abuse rate-limit policies, authorization, and antiforgery
    /// used by password sign-up and sign-in routes.
    /// Safe to call more than once. Hosts must call <c>UseRateLimiter()</c> for the policies to apply.
    /// </summary>
    public static IServiceCollection AddPasswordEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddPasswordSignUpEndpoints();
        services.AddPasswordSignInEndpoints();
        services.AddPasswordRecoveryEndpoints();

        if (services.HasModule<PasswordEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasswordEndpointsModule>();
        return services;
    }

    /// <summary>
    /// Registers the account-abuse rate-limit policy, authorization, antiforgery,
    /// and the logging account-security email sender used when <c>POST /register</c> finds an existing email.
    /// Safe to call more than once. Hosts must call <c>UseRateLimiter()</c> for the policy to apply.
    /// Startup logs a warning while <see cref="LoggingAccountSecurityEmailSender{TUser}"/> is the registered sender.
    /// </summary>
    public static IServiceCollection AddPasswordSignUpEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<PasswordSignUpEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasswordSignUpEndpointsModule>();
        services.AddAccountAbuseRateLimiting();
        services.AddAuthEndpointsAuthorizationAndAntiforgery();
        services.AddAccountSecurityEmailSender();
        return services;
    }

    /// <summary>
    /// Registers the login rate-limit policy and the built-in cookie and Identity bearer completers
    /// used by <c>POST /login</c>.
    /// Safe to call more than once. Hosts must call <c>UseRateLimiter()</c> for the policy to apply.
    /// </summary>
    public static IServiceCollection AddPasswordSignInEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<PasswordSignInEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasswordSignInEndpointsModule>();
        SignInCompleterRegistry.AddIdentityCompleters(services);
        services.AddLoginRateLimiting();
        return services;
    }

    /// <summary>
    /// Registers the account-abuse rate-limit policy used by forgot-password and reset-password.
    /// Safe to call more than once. Hosts must call <c>UseRateLimiter()</c> for the policy to apply.
    /// </summary>
    public static IServiceCollection AddPasswordRecoveryEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.HasModule<PasswordRecoveryEndpointsModule>())
        {
            return services;
        }

        services.AddModule<PasswordRecoveryEndpointsModule>();
        services.AddAccountAbuseRateLimiting();
        return services;
    }
}
