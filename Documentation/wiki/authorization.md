# Simple Authorization

The following code limits access to the MyController to jwt authenticated users:

```cs
using Microsoft.AspNetCore.Authorization;

[Authorize("jwt")]
public class MyController : ControllerBase
{}
```

If you want to apply authorization to an action rather than the controller, apply the `AuthorizeAttribute` attribute to the action itself:

```cs
using Microsoft.AspNetCore.Authorization;

public class MyController : ControllerBase
{
  public ActionResult Get()
  {}  

  [Authorize("jwt")]
  public ActionResult Post() 
  {}
}
```

Read more at [the documentation](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/simple)
