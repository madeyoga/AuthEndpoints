﻿using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.Demo.Controllers;

[ApiController]
[Tags("JSON Web Token")]
public class JwtAuthController // : JwtController<string, MyCustomIdentityUser>
{
    //public JwtAuthController(UserManager<MyCustomIdentityUser> userManager, IAuthenticator<MyCustomIdentityUser> authenticator, IJwtValidator jwtValidator, IOptions<AuthEndpointsOptions> options) : base(userManager, authenticator, jwtValidator, options)
    //{
    //}

    //public override Task<IActionResult> Create([FromBody] SimpleJwtLoginRequest request)
    //{
    //    return base.Create(request);
    //}
}
