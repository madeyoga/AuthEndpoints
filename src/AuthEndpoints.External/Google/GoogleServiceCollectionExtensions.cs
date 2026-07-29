using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.External.Google;

/// <summary>
/// Google OAuth registration for <see cref="ExternalAuthBuilder"/>.
/// </summary>
public static class GoogleServiceCollectionExtensions
{
    /// <summary>
    /// Adds Google as an external authentication provider.
    /// </summary>
    public static ExternalAuthBuilder AddGoogle(
        this ExternalAuthBuilder builder,
        Action<GoogleOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services
            .AddAuthentication()
            .AddGoogle(options =>
            {
                options.SignInScheme = IdentityConstants.ExternalScheme;
                configure(options);
            });

        builder.AddProvider<GoogleExternalAuthProvider>();
        return builder;
    }
}
