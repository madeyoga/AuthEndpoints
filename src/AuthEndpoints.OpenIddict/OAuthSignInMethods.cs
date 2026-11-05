using System.Security.Claims;
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
/// Passkey, email-code, and AuthEndpoints external sign-in record nothing, so <see cref="OAuthSignInMethodCompleter{TUser}"/>
/// and <see cref="OAuthSignInMethodCookieEvents"/> add <c>amr</c> for them when the cookie is written.
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

    /// <summary>The value a cookie sign-in records for a method that records nothing itself.</summary>
    public static string? ForCookie(SignInMethod method) => method switch
    {
        SignInMethod.Passkey => ProofOfPossession,
        SignInMethod.External => Federated,
        SignInMethod.EmailCode => OneTimePassword,
        _ => null, // Password: the completer adds pwd or mfa itself.
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
        foreach (var claim in principal.FindAll(ClaimType))
        {
            if (claim.Value == MultiFactor)
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
/// Wraps a cookie-capable sign-in completer so the cookie written inside it knows the sign-in method.
/// The method is kept in <see cref="HttpContext.Items"/> only while the inner completer runs.
/// </summary>
internal sealed class OAuthSignInMethodCompleter<TUser>(ISignInCompleter<TUser> inner) : ISignInCompleter<TUser>
    where TUser : class
{
    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        var previous = OAuthSignInMethodItem.Read(httpContext);
        OAuthSignInMethodItem.Set(httpContext, context.Method);
        try
        {
            return await inner.CompleteAsync(httpContext, user, context, cancellationToken);
        }
        finally
        {
            OAuthSignInMethodItem.Set(httpContext, previous);
        }
    }

    /// <summary>
    /// Wraps the <c>Cookie</c> and <c>IdentityBearer</c> completers for <typeparamref name="TUser"/>. A closed registration
    /// wins over AuthEndpoints' open generic one whichever is added first, and the inner completer is looked up in the
    /// final service collection when it is first needed. A host that registers its own completer under the same name
    /// afterwards replaces the wrapper, and that completer's cookies get no <c>amr</c> from this package.
    /// </summary>
    public static void Register(IServiceCollection services)
    {
        foreach (var name in new[] { SignInCompleters.Cookie, SignInCompleters.IdentityBearer })
        {
            var existing = services.LastOrDefault(descriptor =>
                descriptor.ServiceType == typeof(ISignInCompleter<TUser>) && Equals(descriptor.ServiceKey, name));
            if (existing is not null)
            {
                // A host completer registered before this package: wrap it in place.
                services.Remove(existing);
                services.AddKeyedScoped<ISignInCompleter<TUser>>(name, (provider, key) => new OAuthSignInMethodCompleter<TUser>(
                    (ISignInCompleter<TUser>)Create(provider, existing, key)));
                continue;
            }

            services.AddKeyedScoped<ISignInCompleter<TUser>>(name, (provider, key) =>
            {
                // AuthEndpoints registers its built-in completers as open generics, possibly after this call.
                var builtIn = services.LastOrDefault(descriptor =>
                    descriptor.ServiceType == typeof(ISignInCompleter<>) && Equals(descriptor.ServiceKey, name))
                    ?? throw new InvalidOperationException(
                        $"No sign-in completer named '{name}' is registered for {typeof(TUser).Name}. Register AuthEndpoints sign-in first.");
                return new OAuthSignInMethodCompleter<TUser>((ISignInCompleter<TUser>)Create(provider, builtIn, key));
            });
        }
    }

    private static object Create(IServiceProvider provider, ServiceDescriptor descriptor, object? key)
    {
        if (descriptor.KeyedImplementationInstance is { } instance)
        {
            return instance;
        }

        if (descriptor.KeyedImplementationFactory is { } factory)
        {
            return factory(provider, key);
        }

        var type = descriptor.KeyedImplementationType!;
        if (type.IsGenericTypeDefinition)
        {
            type = type.MakeGenericType(typeof(TUser));
        }

        return ActivatorUtilities.CreateInstance(provider, type);
    }
}

/// <summary>The sign-in method of the completer that is running in this request, if any.</summary>
internal static class OAuthSignInMethodItem
{
    private static readonly object Key = new();

    public static SignInMethod? Read(HttpContext http)
        => http.Items.TryGetValue(Key, out var value) && value is SignInMethod method ? method : null;

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
                && OAuthSignInMethodItem.Read(context.HttpContext) is { } method
                && OAuthAuthenticationMethods.ForCookie(method) is { } value)
            {
                identity.AddClaim(new Claim(OAuthAuthenticationMethods.ClaimType, value));
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
