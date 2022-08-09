# Working with Custom Identity User

For AuthEndpoints to work with custom identity user,
you need to specify the custom user class for `TUser` on `AddAuthEndpoints<TUser>()`.
For example, my custom identity user:

```cs
public class MyApplicationUser : IdentityUser<Guid>
{
  public string Nickname { get; set; }
}
```

You can simply specify the key type for `TUserKey` and the custom class for `TUser`:

```cs
services.AddAuthEndpointsCore<MyApplicationUser>();
```