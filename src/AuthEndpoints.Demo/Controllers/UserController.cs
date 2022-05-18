using AuthEndpoints.Controllers;
using AuthEndpoints.Demo.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Demo.Controllers;

public class UserController : BaseEndpointsController<string, MyCustomIdentityUser>
{
    public UserController(UserManager<MyCustomIdentityUser> userRepository, IdentityErrorDescriber errorDescriber) : base(userRepository, errorDescriber)
    {
    }
}
