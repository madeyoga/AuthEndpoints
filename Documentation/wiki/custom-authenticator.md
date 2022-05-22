# Writing an Authenticator

By default, AuthEndpoints uses username field and password field to authenticate a user.
If you want to change this behavior, for example, you want to authenticate a user based on email and password,
then you need to implement `IAuthenticator`:

```cs
public class MyAuthenticator : IAuthenticator<IdentityUser>
{
  public async Task<IdentityUser?> Authenticate(string username, string password) 
  {
    TUser user = await userManager.FindByEmailAsync(username);
    if (user == null)
    {
      return null;
    }
    bool correctPassword = await userManager.CheckPasswordAsync(user, password);
    if (!correctPassword)
    {
      return null;
    }
    return user;
  }

  public Task<AuthenticatedUserResponse> Login(IdentityUser user)
  {
    ...
  }
}
```

finally, register it via `AuthEndpointsBuilder`:

```cs
var builder = services.AddAuthEndpoints<string, IdentityUser>();
builder.AddAuthenticator<MyAuthenticator>();
```