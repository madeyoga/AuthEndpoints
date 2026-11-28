using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints;

/// <summary>
/// Adds storage, sign-in methods and sessions after <c>AddAuthEndpoints</c>. Each method calls the matching
/// <c>Add*Endpoints</c> building blocks, so <c>MapAuthEndpoints</c> maps exactly what was added.
/// Calling a method twice adds the union of both calls.
/// </summary>
/// <remarks>
/// Storage comes from a store package, for example <c>AddEntityFrameworkStores&lt;TContext&gt;()</c> from
/// AuthEndpoints.EntityFrameworkCore, or from your own registrations of <c>IUserStore&lt;TUser&gt;</c> and the
/// AuthEndpoints store interfaces.
/// </remarks>
public abstract class AuthEndpointsBuilder
{
    private bool _storesAdded;

    private protected AuthEndpointsBuilder(IServiceCollection services, IdentityBuilder identity)
    {
        Services = services;
        Identity = identity;
    }

    /// <summary>The service collection, for registrations the builder does not cover.</summary>
    public IServiceCollection Services { get; }

    /// <summary>The Identity builder, for token providers and other Identity setup.</summary>
    public IdentityBuilder Identity { get; private set; }

    /// <summary>The user type passed to <c>AddAuthEndpoints</c>.</summary>
    public Type UserType => Identity.UserType;

    /// <summary>
    /// Customizes Identity options. <c>SignIn.RequireConfirmedAccount</c> defaults to true.
    /// </summary>
    public AuthEndpointsBuilder ConfigureIdentity(Action<IdentityOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.Configure(configure);
        return this;
    }

    /// <summary>
    /// Adds Identity roles (<typeparamref name="TRole"/>), so sign-in includes role claims. Call it before
    /// <see cref="AddStores"/> (for example <c>AddEntityFrameworkStores</c>), so the stores include a role store.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The stores were already added, or a different role type is already registered.
    /// </exception>
    public AuthEndpointsBuilder AddRoles<TRole>()
        where TRole : class
    {
        if (Identity.RoleType == typeof(TRole))
        {
            return this;
        }

        if (_storesAdded)
        {
            throw new InvalidOperationException(
                "Call AddRoles before AddEntityFrameworkStores (or AddStores), so the stores include a role store.");
        }

        var registered = Services
            .Select(descriptor => descriptor.ServiceType)
            .FirstOrDefault(type => type.IsGenericType && type.GetGenericTypeDefinition() == typeof(RoleManager<>));
        if (registered is not null && registered.GetGenericArguments()[0] != typeof(TRole))
        {
            throw new InvalidOperationException(
                $"RoleManager<{registered.GetGenericArguments()[0].Name}> is already registered. AddRoles requested RoleManager<{typeof(TRole).Name}>.");
        }

        Identity = Identity.AddRoles<TRole>();
        return this;
    }

    /// <summary>
    /// Registers the stores AuthEndpoints and Identity read and write through. Store packages call this from their own
    /// extension, for example <c>AddEntityFrameworkStores&lt;TContext&gt;()</c>. Call <see cref="AddRoles{TRole}"/> first.
    /// </summary>
    public AuthEndpointsBuilder AddStores(AuthEndpointsStores stores)
    {
        ArgumentNullException.ThrowIfNull(stores);
        RegisterStores(stores);
        _storesAdded = true;
        return this;
    }

    /// <summary>
    /// Adds password sign-in (<c>POST /login</c>, or <c>POST /create</c> for a JWT session), and by default
    /// sign-up (<c>POST /register</c>) and recovery (<c>POST /forgotPassword</c>, <c>POST /resetPassword</c>).
    /// </summary>
    public AuthEndpointsBuilder AddPassword(Action<PasswordFeatureOptions>? configure = null)
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
    public AuthEndpointsBuilder AddPasskeys(Action<PasskeyFeatureOptions>? configure = null)
    {
        var options = new PasskeyFeatureOptions();
        configure?.Invoke(options);

        AddPasskeyEndpoints(options);
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
    public AuthEndpointsBuilder AddEmailCode(Action<EmailCodeOptions>? configure = null)
    {
        AddEmailCodeEndpoints(configure);
        return this;
    }

    /// <summary>
    /// Adds the JWT session, so <c>MapAuthEndpoints</c> can map <see cref="AuthEndpointsSession.Jwt"/>.
    /// </summary>
    public AuthEndpointsBuilder AddJwt(Action<SimpleJwtOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        AddJwtEndpoints(configure);
        return this;
    }

    /// <summary>
    /// Adds the Identity bearer session, so <c>MapAuthEndpoints</c> can map
    /// <see cref="AuthEndpointsSession.IdentityBearer"/>.
    /// </summary>
    public AuthEndpointsBuilder AddIdentityBearer()
    {
        Services.AddBearerSessionEndpoints();
        return this;
    }

    private protected abstract void RegisterStores(AuthEndpointsStores stores);

    private protected abstract void AddPasskeyEndpoints(PasskeyFeatureOptions options);

    private protected abstract void AddEmailCodeEndpoints(Action<EmailCodeOptions>? configure);

    private protected abstract void AddJwtEndpoints(Action<SimpleJwtOptions> configure);
}

internal sealed class AuthEndpointsBuilder<TUser> : AuthEndpointsBuilder
    where TUser : class, new()
{
    internal AuthEndpointsBuilder(IServiceCollection services, IdentityBuilder identity)
        : base(services, identity)
    {
    }

    private protected override void RegisterStores(AuthEndpointsStores stores)
    {
        stores.Register<TUser>(Services, Identity);
    }

    private protected override void AddPasskeyEndpoints(PasskeyFeatureOptions options)
    {
        Services.AddPasskeySignInEndpoints<TUser>();
        if (options.SignUp)
        {
            Services.AddPasskeySignUpEndpoints<TUser>();
            Services.AddPasskeyRegisterOptionsEndpoints();
        }
    }

    private protected override void AddEmailCodeEndpoints(Action<EmailCodeOptions>? configure)
    {
        Services.AddEmailCodeEndpoints<TUser>(configure);
    }

    private protected override void AddJwtEndpoints(Action<SimpleJwtOptions> configure)
    {
        Services.AddJwtEndpoints<TUser>(configure);
    }
}

/// <summary>
/// Registers the stores that ASP.NET Core Identity and AuthEndpoints read and write through. Store packages derive from
/// it and pass an instance to <see cref="AuthEndpointsBuilder.AddStores"/>; AuthEndpoints.EntityFrameworkCore does this in
/// <c>AddEntityFrameworkStores&lt;TContext&gt;()</c>.
/// </summary>
/// <remarks>
/// To use your own storage without a package, register the services directly instead: <c>IUserStore&lt;TUser&gt;</c>
/// (and <c>IRoleStore&lt;TRole&gt;</c> with roles), plus <see cref="IEmailCodeStore"/>, <see cref="IRefreshTokenStore"/>
/// and <c>Sessions.IActiveSessionStore</c> for the features you add.
/// </remarks>
public abstract class AuthEndpointsStores
{
    /// <summary>
    /// Registers the stores for <typeparamref name="TUser"/>. <paramref name="identity"/> carries the role type when
    /// <see cref="AuthEndpointsBuilder.AddRoles{TRole}"/> was called.
    /// </summary>
    public abstract void Register<TUser>(IServiceCollection services, IdentityBuilder identity)
        where TUser : class, new();
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
