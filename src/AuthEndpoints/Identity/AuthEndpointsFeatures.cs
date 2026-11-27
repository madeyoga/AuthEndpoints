using AuthEndpoints.EmailCode;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using AuthEndpoints.Sessions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Identity;

/// <summary>
/// What the host enabled, resolved once from the <c>Add*</c> calls it made.
/// Every <c>Map*</c> decides which routes to map from this record, not from module types,
/// so a question like "can a passkey confirm identity?" has one answer everywhere.
/// </summary>
internal sealed record AuthEndpointsFeatures(
    PasswordFeatures Password,
    PasskeyFeatures Passkeys,
    EmailCodeFeatures EmailCode,
    SessionFeatures Sessions,
    bool AccountManagement,
    bool ExternalAuth,
    bool Jwt,
    bool ActiveSessions)
{
    public static AuthEndpointsFeatures None { get; } = new(
        new PasswordFeatures(Bundle: false, CanSignUp: false, CanSignIn: false, CanRecover: false),
        new PasskeyFeatures(
            Bundle: false,
            CanSignUp: false,
            CanAuthenticate: false,
            CanRequestRegisterOptions: false,
            CanManage: false),
        new EmailCodeFeatures(CanSend: false, CanSignIn: false),
        new SessionFeatures(Cookie: false, IdentityBearer: false),
        AccountManagement: false,
        ExternalAuth: false,
        Jwt: false,
        ActiveSessions: false);

    /// <summary>
    /// Returns the features for <paramref name="services"/>. The record is a singleton once any
    /// <c>Add*</c> module is registered. With none registered, everything is off.
    /// </summary>
    public static AuthEndpointsFeatures For(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return services.GetService<AuthEndpointsFeatures>() ?? None;
    }

    public static AuthEndpointsFeatures For(IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return For(endpoints.ServiceProvider);
    }

    /// <summary>
    /// Throws when a <c>Map*</c> needs a feature the host did not register.
    /// </summary>
    public static void Require(bool enabled, string addMethod, string mapMethod)
    {
        if (!enabled)
        {
            throw new InvalidOperationException($"Call {addMethod} before {mapMethod}.");
        }
    }

    /// <summary>
    /// Reads the module markers. This is the only place that knows which <c>Add*</c> call
    /// turns on which feature; route conditions read the resolved record.
    /// </summary>
    internal static AuthEndpointsFeatures Resolve(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);

        bool Has<TModule>() where TModule : class => AuthEndpointsModules.IsRegistered<TModule>(services);

        // AddPasskeyEndpoints and AddPasswordAuth with a ServerDomain register every passkey module,
        // so the bundle check is a guard for hosts that only have the bundle marker.
        var passkeyBundle = Has<PasskeyEndpointsModule>();

        return new AuthEndpointsFeatures(
            new PasswordFeatures(
                Bundle: Has<PasswordEndpointsModule>(),
                CanSignUp: Has<PasswordSignUpEndpointsModule>(),
                CanSignIn: Has<PasswordSignInEndpointsModule>(),
                CanRecover: Has<PasswordRecoveryEndpointsModule>()),
            new PasskeyFeatures(
                Bundle: passkeyBundle,
                CanSignUp: passkeyBundle || Has<PasskeySignUpEndpointsModule>(),
                CanAuthenticate: passkeyBundle || Has<PasskeySignInEndpointsModule>(),
                CanRequestRegisterOptions: passkeyBundle || Has<PasskeyRegisterOptionsEndpointsModule>(),
                CanManage: passkeyBundle || Has<PasskeyManagementEndpointsModule>()),
            new EmailCodeFeatures(
                CanSend: Has<EmailCodeSendEndpointsModule>(),
                CanSignIn: Has<EmailCodeSignInEndpointsModule>()),
            new SessionFeatures(
                Cookie: Has<CookieSessionEndpointsModule>(),
                IdentityBearer: Has<BearerSessionEndpointsModule>()),
            AccountManagement: Has<AccountManagementEndpointsModule>(),
            ExternalAuth: Has<ExternalAuthEndpointsModule>(),
            Jwt: Has<JwtEndpointsModule>(),
            ActiveSessions: Has<ActiveSessionsModule>());
    }
}

/// <param name="Bundle"><c>AddPasswordEndpoints</c>: sign-up, sign-in, and recovery together.</param>
/// <param name="CanSignUp"><c>POST /register</c>.</param>
/// <param name="CanSignIn">Password <c>POST /login</c> (or JWT <c>POST /create</c>).</param>
/// <param name="CanRecover"><c>POST /forgotPassword</c> and <c>POST /resetPassword</c>.</param>
internal sealed record PasswordFeatures(bool Bundle, bool CanSignUp, bool CanSignIn, bool CanRecover);

/// <param name="Bundle"><c>AddPasskeyEndpoints</c>, or <c>AddPasswordAuth</c> with a passkey server domain.</param>
/// <param name="CanSignUp"><c>POST /passkeys/register</c> for an anonymous caller.</param>
/// <param name="CanAuthenticate">Passkey request options and passkey login.</param>
/// <param name="CanRequestRegisterOptions"><c>POST /passkeys/register/options</c>.</param>
/// <param name="CanManage">Adding, renaming, and removing a signed-in user's passkeys.</param>
internal sealed record PasskeyFeatures(
    bool Bundle,
    bool CanSignUp,
    bool CanAuthenticate,
    bool CanRequestRegisterOptions,
    bool CanManage)
{
    /// <summary>
    /// A passkey can confirm identity whenever the host signs in with passkeys or lets users
    /// manage them, not only with the full bundle (#475).
    /// </summary>
    public bool CanConfirmIdentity => CanAuthenticate || CanManage;
}

/// <param name="CanSend"><c>POST /emailCode/send</c>. Send owns the step-up proof and its rate-limit policy.</param>
/// <param name="CanSignIn"><c>POST /emailCode/verify</c>. Shares the store with send, not the step-up proof.</param>
internal sealed record EmailCodeFeatures(bool CanSend, bool CanSignIn)
{
    /// <summary>
    /// An email code can confirm identity only when send is registered.
    /// <c>AddEmailCodeSignInEndpoints</c> alone does not register the step-up policy.
    /// </summary>
    public bool CanConfirmIdentity => CanSend;
}

/// <param name="Cookie"><c>AddCookieSessionEndpoints</c>.</param>
/// <param name="IdentityBearer"><c>AddBearerSessionEndpoints</c>.</param>
internal sealed record SessionFeatures(bool Cookie, bool IdentityBearer);
