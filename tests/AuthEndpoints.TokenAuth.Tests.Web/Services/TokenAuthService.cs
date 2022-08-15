using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Services;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.TokenAuth.Tests.Web.Services;

public class TokenAuthService<TUser> : IAuthenticator<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> userManager;

    public TokenAuthService(UserManager<TUser> userManager)
    {
        this.userManager = userManager;
    }

    public async Task<TUser?> Authenticate(string username, string password)
    {
        var user = await userManager.FindByNameAsync(username);

        if (user == null)
        {
            return null;
        }

        var correctPassword = await userManager.CheckPasswordAsync(user, password);

        if (!correctPassword)
        {
            return null;
        }

        return user;
    }

    public Task<AuthenticatedUserResponse> Login(TUser user)
    {
        throw new NotImplementedException();
    }
}
