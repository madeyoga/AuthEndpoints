using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Default authenticator. Verifies email/username + password with lockout and confirmed-account checks.
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class DefaultAuthenticator<TUser> : IAuthenticator<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly SignInManager<TUser> _signInManager;

    public DefaultAuthenticator(UserManager<TUser> userManager, SignInManager<TUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    /// <summary>
    /// Verifies credentials. Failed results use a generic invalid-credentials error (no enumeration).
    /// An unknown user runs a password-hash verify, new in 4.0, so that path matches a wrong password.
    /// </summary>
    public async Task<AuthenticationResult<TUser>> AuthenticateAsync(string username, string password)
    {
        var invalid = AuthenticationResult<TUser>.Failed(new AuthenticationError
        {
            Code = "invalid_credentials",
            Description = "Invalid credentials.",
        });

        var user = await _userManager.FindByEmailAsync(username)
            ?? await _userManager.FindByNameAsync(username);

        if (user == null)
        {
            PasswordHashTiming<TUser>.VerifyUnknownUser(_userManager.PasswordHasher, password);
            return invalid;
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            return invalid;
        }

        return AuthenticationResult<TUser>.Success(user);
    }
}
