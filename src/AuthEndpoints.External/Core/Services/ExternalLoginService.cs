using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.External;

/// <summary>
/// Resolves or creates a local user from external login info and links the provider login.
/// </summary>
public sealed class ExternalLoginService<TUser>
    where TUser : class, new()
{
    private readonly SignInManager<TUser> _signInManager;
    private readonly UserManager<TUser> _userManager;
    private readonly IUserStore<TUser> _userStore;

    public ExternalLoginService(
        SignInManager<TUser> signInManager,
        UserManager<TUser> userManager,
        IUserStore<TUser> userStore)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _userStore = userStore;
    }

    public async Task<ExternalLoginProvisionResult<TUser>> ProvisionAsync(
        CancellationToken cancellationToken = default)
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            return ExternalLoginProvisionResult<TUser>.Failed(
                Results.Problem(
                    detail: "External login information was not found. Complete the OAuth challenge first.",
                    statusCode: StatusCodes.Status400BadRequest));
        }

        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (user is null)
        {
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
            {
                return ExternalLoginProvisionResult<TUser>.Failed(
                    Results.Problem(
                        detail: "The external provider did not return an email claim.",
                        statusCode: StatusCodes.Status400BadRequest));
            }

            user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                user = new TUser();
                await _userStore.SetUserNameAsync(user, email, cancellationToken);

                if (_userStore is IUserEmailStore<TUser> emailStore)
                {
                    await emailStore.SetEmailAsync(user, email, cancellationToken);
                    // Trust verified email from the OAuth provider so RequireConfirmedAccount hosts can sign in.
                    await emailStore.SetEmailConfirmedAsync(user, true, cancellationToken);
                }

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    return ExternalLoginProvisionResult<TUser>.Failed(
                        Results.Problem(
                            detail: string.Join(" ", createResult.Errors.Select(e => e.Description)),
                            statusCode: StatusCodes.Status400BadRequest));
                }
            }

            var linkResult = await _userManager.AddLoginAsync(user, info);
            if (!linkResult.Succeeded)
            {
                return ExternalLoginProvisionResult<TUser>.Failed(
                    Results.Problem(
                        detail: string.Join(" ", linkResult.Errors.Select(e => e.Description)),
                        statusCode: StatusCodes.Status400BadRequest));
            }
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return ExternalLoginProvisionResult<TUser>.Failed(
                Results.Problem(detail: "User is locked out.", statusCode: StatusCodes.Status401Unauthorized));
        }

        if (!await _signInManager.CanSignInAsync(user))
        {
            return ExternalLoginProvisionResult<TUser>.Failed(
                Results.Problem(detail: "User is not allowed to sign in.", statusCode: StatusCodes.Status401Unauthorized));
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
    public IResult? ErrorResult { get; private init; }

    public static ExternalLoginProvisionResult<TUser> Success(TUser user, ExternalLoginInfo info) => new()
    {
        Succeeded = true,
        User = user,
        Info = info,
    };

    public static ExternalLoginProvisionResult<TUser> Failed(IResult error) => new()
    {
        Succeeded = false,
        ErrorResult = error,
    };
}
