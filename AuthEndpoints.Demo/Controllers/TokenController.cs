using AuthEndpoints.Controllers;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Services.Authenticators;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Demo.Controllers;
public class TokenController : TokenEndpointsController<string, MyCustomIdentityUser>
{
    public TokenController(UserManager<MyCustomIdentityUser> userRepository, TokenUserAuthenticator<MyCustomIdentityUser> authenticator) : base(userRepository, authenticator)
    {
    }
}
