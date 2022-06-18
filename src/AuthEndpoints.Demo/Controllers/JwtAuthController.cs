using AuthEndpoints.Controllers;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Demo.Controllers;

[ApiController]
[Tags("JSON Web Token")]
public class JwtAuthController // : JwtController<string, MyCustomIdentityUser>
{
    //public JwtAuthController(UserManager<MyCustomIdentityUser> userManager, IAuthenticator<MyCustomIdentityUser> authenticator, IJwtValidator jwtValidator, IOptions<AuthEndpointsOptions> options) : base(userManager, authenticator, jwtValidator, options)
    //{
    //}

    //public override Task<IActionResult> Create([FromBody] LoginRequest request)
    //{
    //    return base.Create(request);
    //}
}
