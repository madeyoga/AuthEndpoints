using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Resolves or creates a local user from external login info and links the provider login.
/// </summary>
public sealed class ExternalLoginService<TUser>
    where TUser : class, new()
{
    private readonly SignInManager<TUser> _signInManager;
    private readonly UserManager<TUser> _userManager;
    private readonly IUserStore<TUser> _userStore;
    private readonly ExternalAuthOptions _options;

    public ExternalLoginService(
        SignInManager<TUser> signInManager,
        UserManager<TUser> userManager,
        IUserStore<TUser> userStore,
        IOptions<ExternalAuthOptions> options)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _userStore = userStore;
        _options = options.Value;
    }

    public async Task<ExternalLoginProvisionResult<TUser>> ProvisionAsync(
        CancellationToken cancellationToken = default)
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            return ExternalLoginProvisionResult<TUser>.Failed(
                "external_login_info_missing",
                "External login information was not found. Complete the OAuth challenge first.",
                StatusCodes.Status400BadRequest);
        }

        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (user is null)
        {
            var email = ExternalEmailClaims.GetEmail(info.Principal);
            if (string.IsNullOrEmpty(email))
            {
                return ExternalLoginProvisionResult<TUser>.Failed(
                    "email_missing",
                    "The external provider did not return an email claim.",
                    StatusCodes.Status400BadRequest);
            }

            var emailVerified = ExternalEmailClaims.IsEmailVerified(info.Principal);
            if (_options.RequireVerifiedEmail && !emailVerified)
            {
                return ExternalLoginProvisionResult<TUser>.Failed(
                    "email_unverified",
                    "The external provider did not return a verified email.",
                    StatusCodes.Status400BadRequest);
            }

            user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                user = new TUser();
                await _userStore.SetUserNameAsync(user, email, cancellationToken);

                if (_userStore is IUserEmailStore<TUser> emailStore)
                {
                    await emailStore.SetEmailAsync(user, email, cancellationToken);
                    await emailStore.SetEmailConfirmedAsync(user, emailVerified, cancellationToken);
                }

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    return ExternalLoginProvisionResult<TUser>.Failed(
                        "user_create_failed",
                        string.Join(" ", createResult.Errors.Select(e => e.Description)),
                        StatusCodes.Status400BadRequest);
                }
            }
            else
            {
                if (!_options.AutoLinkByEmail)
                {
                    return ExternalLoginProvisionResult<TUser>.Failed(
                        "auto_link_disabled",
                        "A local account with this email already exists. Sign in and link the provider from account settings.",
                        StatusCodes.Status400BadRequest);
                }

                if (_options.RequireVerifiedEmail && !emailVerified)
                {
                    return ExternalLoginProvisionResult<TUser>.Failed(
                        "email_unverified",
                        "Cannot link to an existing account without a verified email from the provider.",
                        StatusCodes.Status400BadRequest);
                }
            }

            var linkResult = await _userManager.AddLoginAsync(user, info);
            if (!linkResult.Succeeded)
            {
                return ExternalLoginProvisionResult<TUser>.Failed(
                    "login_link_failed",
                    string.Join(" ", linkResult.Errors.Select(e => e.Description)),
                    StatusCodes.Status400BadRequest);
            }
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return ExternalLoginProvisionResult<TUser>.Failed(
                "user_locked_out",
                "User is locked out.",
                StatusCodes.Status401Unauthorized);
        }

        if (!await _signInManager.CanSignInAsync(user))
        {
            return ExternalLoginProvisionResult<TUser>.Failed(
                "user_not_allowed",
                "User is not allowed to sign in.",
                StatusCodes.Status401Unauthorized);
        }

        return ExternalLoginProvisionResult<TUser>.Success(user, info);
    }
}

/// <summary>
/// Result of provisioning a local user from an external login.
/// </summary>
public sealed class ExternalLoginProvisionResult<TUser>
    where TUser : class
{
    public bool Succeeded { get; private init; }
    public TUser? User { get; private init; }
    public ExternalLoginInfo? Info { get; private init; }
    public string? Error { get; private init; }
    public string? ErrorDescription { get; private init; }
    public int StatusCode { get; private init; }

    public static ExternalLoginProvisionResult<TUser> Success(TUser user, ExternalLoginInfo info) => new()
    {
        Succeeded = true,
        User = user,
        Info = info,
    };

    public static ExternalLoginProvisionResult<TUser> Failed(string error, string description, int statusCode) => new()
    {
        Succeeded = false,
        Error = error,
        ErrorDescription = description,
        StatusCode = statusCode,
    };
}
