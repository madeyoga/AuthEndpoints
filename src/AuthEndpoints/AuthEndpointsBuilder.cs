using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints;

/// <summary>
/// Adds sign-in methods and sessions after <c>AddAuthEndpoints</c>. Each method calls the matching
/// <c>Add*Endpoints</c> building blocks, so <c>MapAuthEndpoints</c> maps exactly what was added.
/// Calling a method twice adds the union of both calls.
/// </summary>
public sealed class AuthEndpointsBuilder<TUser, TContext>
    where TUser : class, new()
    where TContext : DbContext
{
    internal AuthEndpointsBuilder(IServiceCollection services, IdentityBuilder identity)
    {
        Services = services;
        Identity = identity;
    }

    /// <summary>The service collection, for registrations the builder does not cover.</summary>
    public IServiceCollection Services { get; }

    /// <summary>The Identity builder, for token providers and other Identity setup.</summary>
    public IdentityBuilder Identity { get; }

    /// <summary>
    /// Customizes Identity options. <c>SignIn.RequireConfirmedAccount</c> defaults to true.
    /// </summary>
    public AuthEndpointsBuilder<TUser, TContext> ConfigureIdentity(Action<IdentityOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.Configure(configure);
        return this;
    }

    /// <summary>
    /// Adds password sign-in (<c>POST /login</c>, or <c>POST /create</c> for a JWT session), and by default
    /// sign-up (<c>POST /register</c>) and recovery (<c>POST /forgotPassword</c>, <c>POST /resetPassword</c>).
    /// </summary>
    public AuthEndpointsBuilder<TUser, TContext> AddPassword(Action<PasswordFeatureOptions>? configure = null)
    {
        var options = new PasswordFeatureOptions();
        configure?.Invoke(options);

        Services.AddPasswordSignInEndpoints();
        if (options.SignUp)
        {
            Services.AddPasswordSignUpEndpoints();
        }

        if (options.Recovery)
        {
            Services.AddPasswordRecoveryEndpoints();
        }

        return this;
    }

    /// <summary>
    /// Adds passkey sign-in, and by default anonymous passkey sign-up and management of a signed-in user's passkeys.
    /// A passkey can also confirm identity for step-up.
    /// Hosts must serve over HTTPS and set <see cref="PasskeyFeatureOptions.ServerDomain"/> (or
    /// <c>IdentityPasskeyOptions.ServerDomain</c>) in Production.
    /// </summary>
    public AuthEndpointsBuilder<TUser, TContext> AddPasskeys(Action<PasskeyFeatureOptions>? configure = null)
    {
        var options = new PasskeyFeatureOptions();
        configure?.Invoke(options);

        Services.AddPasskeySignInEndpoints<TUser>();
        if (options.SignUp)
        {
            Services.AddPasskeySignUpEndpoints<TUser>();
            Services.AddPasskeyRegisterOptionsEndpoints();
        }

        if (options.Management)
        {
            Services.AddPasskeyManagementEndpoints();
        }

        if (!string.IsNullOrWhiteSpace(options.ServerDomain))
        {
            var serverDomain = options.ServerDomain;
            Services.Configure<IdentityPasskeyOptions>(passkeys => passkeys.ServerDomain = serverDomain);
        }

        return this;
    }

    /// <summary>
    /// Adds email-code send (<c>POST /emailCode/send</c>) and sign-in (<c>POST /emailCode/verify</c>).
    /// A passwordless account can also confirm identity with an email code.
    /// </summary>
    public AuthEndpointsBuilder<TUser, TContext> AddEmailCode(Action<EmailCodeOptions>? configure = null)
    {
        Services.AddEmailCodeEndpoints<TUser, TContext>(configure);
        return this;
    }

    /// <summary>
    /// Adds the JWT session, so <c>MapAuthEndpoints</c> can map <see cref="AuthEndpointsSession.Jwt"/>.
    /// </summary>
    public AuthEndpointsBuilder<TUser, TContext> AddJwt(Action<SimpleJwtOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.AddJwtEndpoints<TUser, TContext>(configure);
        return this;
    }

    /// <summary>
    /// Adds the Identity bearer session, so <c>MapAuthEndpoints</c> can map
    /// <see cref="AuthEndpointsSession.IdentityBearer"/>.
    /// </summary>
    public AuthEndpointsBuilder<TUser, TContext> AddIdentityBearer()
    {
        Services.AddBearerSessionEndpoints();
        return this;
    }
}

/// <summary>Which password routes <c>AddPassword</c> adds. Sign-in is always added.</summary>
public sealed class PasswordFeatureOptions
{
    /// <summary>Adds <c>POST /register</c>. Default: true.</summary>
    public bool SignUp { get; set; } = true;

    /// <summary>Adds <c>POST /forgotPassword</c> and <c>POST /resetPassword</c>. Default: true.</summary>
    public bool Recovery { get; set; } = true;
}

/// <summary>Which passkey routes <c>AddPasskeys</c> adds. Sign-in is always added.</summary>
public sealed class PasskeyFeatureOptions
{
    /// <summary>
    /// WebAuthn relying-party domain (for example <c>example.com</c>). Sets <c>IdentityPasskeyOptions.ServerDomain</c>.
    /// </summary>
    public string? ServerDomain { get; set; }

    /// <summary>
    /// Adds anonymous passkey sign-up: <c>POST /passkeys/register/options</c> and <c>POST /passkeys/register</c>.
    /// Default: true.
    /// </summary>
    public bool SignUp { get; set; } = true;

    /// <summary>Adds listing, adding, renaming, and removing a signed-in user's passkeys. Default: true.</summary>
    public bool Management { get; set; } = true;
}
