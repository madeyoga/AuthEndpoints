using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Default authenticator. Authenticate user by username and password.
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class DefaultAuthenticator<TUser> : IAuthenticator<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> userManager;

    public DefaultAuthenticator(UserManager<TUser> userManager)
    {
        this.userManager = userManager;
    }

    /// <summary>
    /// Use this method to verify a set of credentials. It takes credentials as argument, username and password for the default case.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <returns>An instance of TUser if credentials are valid</returns>
    public async Task<AuthenticationResult<TUser>> AuthenticateAsync(string username, string password)
    {
        var user = await userManager.FindByNameAsync(username);

        if (user == null)
        {
            return AuthenticationResult<TUser>.Failed(new AuthenticationError()
            {
                Code = "invalid_credentials",
                Description = "Invalid credentials username or password.",
            });
        }

        var correctPassword = await userManager.CheckPasswordAsync(user, password);

        if (!correctPassword)
        {
            return AuthenticationResult<TUser>.Failed(new AuthenticationError()
            {
                Code = "invalid_credentials",
                Description = "Invalid credentials username or password.",
            });
        }

        return AuthenticationResult<TUser>.Success(user);
    }
}
