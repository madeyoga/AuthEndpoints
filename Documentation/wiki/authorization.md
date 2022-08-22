# Authorize with JWT bearer authentication scheme

The following code limits access to the MyController to jwt authenticated users:

```cs
using Microsoft.AspNetCore.Authorization;

[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
public class MyController : ControllerBase
{}
```

If you want to apply authorization to an action rather than the controller, apply the `Authorize` attribute to the action itself:

```cs
using Microsoft.AspNetCore.Authorization;

public class MyController : ControllerBase
{
  public ActionResult Get()
  {}

  [Authorize(AuthenticationSchemes = "jwt")]
  public ActionResult Post() 
  {}
}
```

Read more about authorization with a specific scheme at [the documentation](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/limitingidentitybyscheme)
