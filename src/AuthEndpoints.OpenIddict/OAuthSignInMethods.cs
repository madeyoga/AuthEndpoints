using System.Security.Claims;
using AuthEndpoints.EmailCode;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// The <c>amr</c> (RFC 8176) values for the ID token, read from the sign-in cookie.
/// <para>
/// What the Identity cookie records today: AuthEndpoints password sign-in adds <c>amr=pwd</c>, and <c>amr=mfa</c> when an
/// authenticator or recovery code was used. Identity's own <c>PasswordSignInAsync</c> and <c>TwoFactorSignInAsync</c> do the
/// same, and Identity's external sign-in adds <see cref="ClaimTypes.AuthenticationMethod"/> with the provider name.
/// Passkey, email-code, and AuthEndpoints external sign-in record nothing, so <see cref="OAuthSignInMethodRegistration{TUser}"/>
/// wraps the completers and <see cref="OAuthSignInMethodCookieEvents"/> adds <c>amr</c> for them when the cookie is written.
/// </para>
/// </summary>
internal static class OAuthAuthenticationMethods
{
    public const string ClaimType = "amr";
    public const string Password = "pwd";
    public const string OneTimePassword = "otp";
    public const string MultiFactor = "mfa";
    public const string ProofOfPossession = "pop";

    /// <summary>Not in RFC 8176. Used by Microsoft Entra ID for a federated (external provider) sign-in.</summary>
    public const string Federated = "fed";

    /// <summary>
    /// The values a cookie sign-in records for a method that records nothing itself. A passkey is multi-factor
    /// (the key, plus the PIN or biometric that unlocked it) when Identity requires user verification: it then rejects
    /// any assertion without the user-verified flag. That is the .NET default.
    /// </summary>
    public static string[] ForCookie(SignInMethod method, string? passkeyUserVerification) => method switch
    {
        SignInMethod.Passkey when string.Equals(passkeyUserVerification, "required", StringComparison.OrdinalIgnoreCase)
            => [ProofOfPossession, MultiFactor],
        SignInMethod.Passkey => [ProofOfPossession],
        SignInMethod.External => [Federated],
        SignInMethod.EmailCode => [OneTimePassword],
        _ => [], // Password: the completer adds pwd or mfa itself.
    };

    /// <summary>The ID token values for a signed-in cookie principal, in a stable order. Empty when the method is unknown.</summary>
    public static string[] FromPrincipal(ClaimsPrincipal? principal)
    {
        if (principal is null)
        {
            return [];
        }

        var external = principal.HasClaim(claim => claim.Type == ClaimTypes.AuthenticationMethod && !string.IsNullOrEmpty(claim.Value));
        var values = new List<string>();
        var claims = principal.FindAll(ClaimType).ToList();
        foreach (var claim in claims)
        {
            // A lone mfa is what Identity and AuthEndpoints write after a second factor. Anything else is kept as written.
            if (claim.Value == MultiFactor && claims.Count == 1)
            {
                // Identity's two-factor step follows a password, or an external sign-in when it recorded the provider.
                // Both authenticator and recovery codes are one-time codes.
                Add(values, external ? Federated : Password);
                Add(values, OneTimePassword);
                Add(values, MultiFactor);
            }
            else if (IsValue(claim.Value))
            {
                Add(values, claim.Value);
            }
        }

        if (values.Count == 0 && external)
        {
            values.Add(Federated);
        }

        return values.ToArray();
    }

    public static string? Join(string[] values)
    {
        var joined = string.Join(' ', values);
        return joined.Length is 0 or > OAuthRequestLimits.AuthenticationMethodsLength ? null : joined;
    }

    private static void Add(List<string> values, string value)
    {
        if (!values.Contains(value))
        {
            values.Add(value);
        }
    }

    // RFC 8176 values are short lowercase tokens. Anything else a host put in amr is dropped.
    private static bool IsValue(string value)
        => value.Length is > 0 and <= 32 && value.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-');
}

/// <summary>
/// Wraps a sign-in completer so the cookie written inside it knows the sign-in method.
/// The method is kept in <see cref="HttpContext.Items"/> only while the inner completer runs.
/// </summary>
internal sealed class OAuthSignInMethodCompleter<TUser>(ISignInCompleter<TUser> inner) : ISignInCompleter<TUser>
    where TUser : class
{
    public Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
        => OAuthSignInMethodItem.RunAsync(httpContext, context.Method, () => inner.CompleteAsync(httpContext, user, context, cancellationToken));
}

#pragma warning disable CS0618 // The obsolete completer interfaces are still called by AuthEndpoints when a host registers its own.
internal sealed class OAuthPasskeySignInMethodCompleter<TUser>(IPasskeySignInCompleter<TUser> inner) : IPasskeySignInCompleter<TUser>
    where TUser : class
{
    public Task<IResult> CompleteAsync(
        HttpContext httpContext, TUser user, PasskeySignInCompletionContext context, CancellationToken cancellationToken = default)
        => OAuthSignInMethodItem.RunAsync(httpContext, SignInMethod.Passkey, () => inner.CompleteAsync(httpContext, user, context, cancellationToken));
}

internal sealed class OAuthEmailCodeSignInMethodCompleter<TUser>(IEmailCodeSignInCompleter<TUser> inner) : IEmailCodeSignInCompleter<TUser>
    where TUser : class
{
    public Task<IResult> CompleteAsync(
        HttpContext httpContext, TUser user, EmailCodeSignInContext context, CancellationToken cancellationToken = default)
        => OAuthSignInMethodItem.RunAsync(httpContext, SignInMethod.EmailCode, () => inner.CompleteAsync(httpContext, user, context, cancellationToken));
}

internal sealed class OAuthExternalSignInMethodCompleter<TUser>(IExternalLoginCompleter<TUser> inner) : IExternalLoginCompleter<TUser>
    where TUser : class
{
    public Task<IResult> CompleteAsync(
        HttpContext httpContext, TUser user, ExternalLoginInfo info, string? returnUrl, CancellationToken cancellationToken = default)
        => OAuthSignInMethodItem.RunAsync(httpContext, SignInMethod.External, () => inner.CompleteAsync(httpContext, user, info, returnUrl, cancellationToken));
}

/// <summary>
/// Registers the wrappers for <typeparamref name="TUser"/>.
/// <list type="bullet">
/// <item>Every <see cref="ISignInCompleter{TUser}"/> already registered under any name, the host's own included, is wrapped
/// in place.</item>
/// <item>The built-in <c>Cookie</c> and <c>IdentityBearer</c> completers are wrapped whichever is registered first: a closed
/// registration wins over AuthEndpoints' open generic one, and the open generic is looked up when first needed.</item>
/// <item>A host's own obsolete <see cref="IPasskeySignInCompleter{TUser}"/>, <see cref="IEmailCodeSignInCompleter{TUser}"/>, or
/// <see cref="IExternalLoginCompleter{TUser}"/> is wrapped too. The built-in ones are returned unwrapped, because
/// AuthEndpoints routes to an obsolete completer only when it is not the built-in type, and wrapping one would change that.</item>
/// </list>
/// A completer registered after this call is not wrapped. <see cref="OAuthSignInMethodAudit"/> names it at startup.
/// </summary>
internal static class OAuthSignInMethodRegistration<TUser>
    where TUser : class
{
    public static void Register(IServiceCollection services)
    {
        var ours = new HashSet<ServiceDescriptor>();
        foreach (var existing in services.Where(descriptor => descriptor.ServiceType == typeof(ISignInCompleter<TUser>) && descriptor.IsKeyedService).ToList())
        {
            var index = services.IndexOf(existing);
            services[index] = ServiceDescriptor.KeyedScoped<ISignInCompleter<TUser>>(existing.ServiceKey, (provider, key)
                => new OAuthSignInMethodCompleter<TUser>((ISignInCompleter<TUser>)Create(provider, existing, key)));
            ours.Add(services[index]);
        }

        foreach (var name in new[] { SignInCompleters.Cookie, SignInCompleters.IdentityBearer })
        {
            if (services.Any(descriptor => descriptor.ServiceType == typeof(ISignInCompleter<TUser>) && Equals(descriptor.ServiceKey, name)))
            {
                continue;
            }

            var descriptor = ServiceDescriptor.KeyedScoped<ISignInCompleter<TUser>>(name, (provider, key) =>
            {
                // AuthEndpoints registers its built-in completers as open generics, possibly after this call.
                var builtIn = services.LastOrDefault(item =>
                    item.ServiceType == typeof(ISignInCompleter<>) && Equals(item.ServiceKey, name))
                    ?? throw new InvalidOperationException(
                        $"No sign-in completer named '{name}' is registered for {typeof(TUser).Name}. Register AuthEndpoints sign-in first.");
                return new OAuthSignInMethodCompleter<TUser>((ISignInCompleter<TUser>)Create(provider, builtIn, key));
            });
            services.Add(descriptor);
            ours.Add(descriptor);
        }

        WrapLegacy<IPasskeySignInCompleter<TUser>>(services, ours, typeof(IdentityPasskeySignInCompleter<TUser>), inner => new OAuthPasskeySignInMethodCompleter<TUser>(inner));
        WrapLegacy<IEmailCodeSignInCompleter<TUser>>(services, ours, typeof(IdentityEmailCodeSignInCompleter<TUser>), inner => new OAuthEmailCodeSignInMethodCompleter<TUser>(inner));
        WrapLegacy<IExternalLoginCompleter<TUser>>(services, ours, typeof(CookieExternalLoginCompleter<TUser>), inner => new OAuthExternalSignInMethodCompleter<TUser>(inner));
        services.AddSingleton<OAuthSignInMethodAudit>(new OAuthSignInMethodAudit<TUser>(services, ours));
    }

    private static void WrapLegacy<TService>(
        IServiceCollection services, HashSet<ServiceDescriptor> ours, Type builtIn, Func<TService, TService> wrap)
        where TService : class
    {
        foreach (var existing in services.Where(descriptor => descriptor.ServiceType == typeof(TService) && !descriptor.IsKeyedService).ToList())
        {
            if (existing.ImplementationType == builtIn)
            {
                continue;
            }

            var index = services.IndexOf(existing);
            services[index] = new ServiceDescriptor(typeof(TService), provider =>
            {
                var inner = (TService)Create(provider, existing, null);
                return inner.GetType() == builtIn ? inner : wrap(inner);
            }, existing.Lifetime);
            ours.Add(services[index]);
        }
    }

    private static object Create(IServiceProvider provider, ServiceDescriptor descriptor, object? key)
    {
        if (descriptor.IsKeyedService)
        {
            if (descriptor.KeyedImplementationInstance is { } keyedInstance)
            {
                return keyedInstance;
            }

            if (descriptor.KeyedImplementationFactory is { } keyedFactory)
            {
                return keyedFactory(provider, key);
            }

            return Activate(provider, descriptor.KeyedImplementationType!);
        }

        return descriptor.ImplementationInstance
            ?? descriptor.ImplementationFactory?.Invoke(provider)
            ?? Activate(provider, descriptor.ImplementationType!);
    }

    private static object Activate(IServiceProvider provider, Type type)
        => ActivatorUtilities.CreateInstance(provider, type.IsGenericTypeDefinition ? type.MakeGenericType(typeof(TUser)) : type);
}
#pragma warning restore CS0618

/// <summary>Finds sign-in completers registered after <c>AddOAuthServer</c>, whose cookies get no <c>amr</c>.</summary>
internal abstract class OAuthSignInMethodAudit
{
    public abstract IReadOnlyList<string> Unwrapped();
}

#pragma warning disable CS0618
internal sealed class OAuthSignInMethodAudit<TUser>(IServiceCollection services, HashSet<ServiceDescriptor> ours) : OAuthSignInMethodAudit
    where TUser : class
{
    public override IReadOnlyList<string> Unwrapped()
    {
        var builtIns = new[]
        {
            typeof(IdentityPasskeySignInCompleter<TUser>),
            typeof(IdentityEmailCodeSignInCompleter<TUser>),
            typeof(CookieExternalLoginCompleter<TUser>),
        };
        var types = new[]
        {
            typeof(ISignInCompleter<TUser>),
            typeof(IPasskeySignInCompleter<TUser>),
            typeof(IEmailCodeSignInCompleter<TUser>),
            typeof(IExternalLoginCompleter<TUser>),
        };
        return services
            .Where(descriptor => types.Contains(descriptor.ServiceType) && !ours.Contains(descriptor))
            .Where(descriptor => !builtIns.Contains(descriptor.IsKeyedService ? descriptor.KeyedImplementationType : descriptor.ImplementationType))
            .Select(descriptor => descriptor.IsKeyedService
                ? $"{descriptor.ServiceType.Name.Split('`')[0]} '{descriptor.ServiceKey}'"
                : descriptor.ServiceType.Name.Split('`')[0])
            .Distinct()
            .ToList();
    }
}
#pragma warning restore CS0618

/// <summary>The sign-in method of the completer that is running in this request, if any.</summary>
internal static class OAuthSignInMethodItem
{
    private static readonly object Key = new();

    public static SignInMethod? Read(HttpContext http)
        => http.Items.TryGetValue(Key, out var value) && value is SignInMethod method ? method : null;

    public static async Task<IResult> RunAsync(HttpContext http, SignInMethod method, Func<Task<IResult>> inner)
    {
        var previous = Read(http);
        Set(http, method);
        try
        {
            return await inner();
        }
        finally
        {
            Set(http, previous);
        }
    }

    public static void Set(HttpContext http, SignInMethod? method)
    {
        if (method is { } value)
        {
            http.Items[Key] = value;
        }
        else
        {
            http.Items.Remove(Key);
        }
    }
}

/// <summary>
/// Adds <c>amr</c> to the sign-in cookie for methods that record none (passkey, external, email code), and keeps
/// <c>amr</c> when Identity refreshes the cookie after its security stamp check. Only with OpenID Connect on.
/// </summary>
internal sealed class OAuthSignInMethodCookieEvents(IOptions<OAuthServerOptions> oauth)
    : IPostConfigureOptions<CookieAuthenticationOptions>, IPostConfigureOptions<SecurityStampValidatorOptions>
{
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        if (Settings() is not { OpenIdConnectEnabled: true } settings || name != settings.AuthenticationScheme)
        {
            return;
        }

        var previous = options.Events.OnSigningIn;
        options.Events.OnSigningIn = context =>
        {
            if (context.Principal?.Identity is ClaimsIdentity identity
                && !context.Principal.HasClaim(claim => claim.Type == OAuthAuthenticationMethods.ClaimType)
                && OAuthSignInMethodItem.Read(context.HttpContext) is { } method)
            {
                var verification = context.HttpContext.RequestServices.GetService<IOptions<IdentityPasskeyOptions>>()?.Value.UserVerificationRequirement;
                foreach (var value in OAuthAuthenticationMethods.ForCookie(method, verification))
                {
                    identity.AddClaim(new Claim(OAuthAuthenticationMethods.ClaimType, value));
                }
            }

            return previous(context);
        };
    }

    public void PostConfigure(string? name, SecurityStampValidatorOptions options)
    {
        if (Settings() is not { OpenIdConnectEnabled: true })
        {
            return;
        }

        // Identity rebuilds the principal from the user every ValidationInterval and drops amr. The session is the same,
        // so how the user signed in still holds. RefreshSignInAsync already keeps these claims.
        var previous = options.OnRefreshingPrincipal;
        options.OnRefreshingPrincipal = context =>
        {
            if (context.NewPrincipal?.Identity is ClaimsIdentity identity && context.CurrentPrincipal is { } current)
            {
                foreach (var type in new[] { OAuthAuthenticationMethods.ClaimType, ClaimTypes.AuthenticationMethod })
                {
                    if (!identity.HasClaim(claim => claim.Type == type))
                    {
                        foreach (var claim in current.FindAll(type))
                        {
                            identity.AddClaim(new Claim(claim.Type, claim.Value, claim.ValueType, claim.Issuer));
                        }
                    }
                }
            }

            return previous?.Invoke(context) ?? Task.CompletedTask;
        };
    }

    private OAuthServerOptions? Settings()
    {
        try
        {
            return oauth.Value;
        }
        catch (OptionsValidationException)
        {
            // Startup validation reports the problem. Do not fail cookie setup for it.
            return null;
        }
    }
}
