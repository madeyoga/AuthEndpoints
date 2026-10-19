using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints;

/// <summary>
/// What a successful sign-in already proved, plus the query flags the client sent.
/// Built-in completers read the flags they honor and ignore the rest.
/// </summary>
public sealed class SignInCompletionContext
{
    public required SignInMethod Method { get; init; }

    /// <summary>
    /// <c>useCookies</c> query flag. Honored by <see cref="SignInCompleters.IdentityBearer"/> only.
    /// </summary>
    public bool? UseCookies { get; init; }

    /// <summary>
    /// <c>useSessionCookies</c> query flag. Honored by <see cref="SignInCompleters.IdentityBearer"/>
    /// and by <see cref="SignInCompleters.Cookie"/> (persistent only when this is <see langword="false"/>).
    /// </summary>
    public bool? UseSessionCookies { get; init; }

    /// <summary>
    /// Password sign-in presented a valid authenticator or recovery code in this request.
    /// Cookie and Identity bearer completers add an <c>amr</c> claim of <c>mfa</c> when this is set,
    /// and <c>pwd</c> otherwise (including a remembered two-factor client).
    /// </summary>
    public bool UsedTwoFactor { get; init; }

    /// <summary>
    /// Password sign-in with a valid authenticator code on a persistent application cookie.
    /// Honored by <see cref="SignInCompleters.Cookie"/> and <see cref="SignInCompleters.IdentityBearer"/>
    /// when the application cookie is the scheme being issued.
    /// </summary>
    public bool RememberTwoFactorClient { get; init; }

    /// <summary>
    /// The account was created in this request (email-code sign-up, passkey register, or external create).
    /// </summary>
    public bool IsNewUser { get; init; }

    /// <summary>
    /// Passkey ceremony kind. Set only for <see cref="SignInMethod.Passkey"/>.
    /// </summary>
    public PasskeySignInKind? PasskeyKind { get; init; }

    /// <summary>
    /// Passkey register credential id. Cookie register returns <c>200 { credentialId }</c>.
    /// </summary>
    public byte[]? PasskeyCredentialId { get; init; }

    /// <summary>
    /// External login that was linked or created. Set only for <see cref="SignInMethod.External"/>.
    /// </summary>
    public ExternalLoginInfo? ExternalLogin { get; init; }

    /// <summary>
    /// External return URL, already validated by the external callback. Set only for <see cref="SignInMethod.External"/>.
    /// </summary>
    public string? ReturnUrl { get; init; }
}
