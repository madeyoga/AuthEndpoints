# Writing an Authenticator

By default, AuthEndpoints authenticate users via username.
If you want to change this behavior, for example, you want to authenticate a user via email,
then you need to write a custom authenticator. Something like this will work:

```cs
public class MyAuthenticator : IAuthenticator<IdentityUser>
{
  public async Task<IdentityUser?> Authenticate(string email, string password) 
  {
    var user = await userManager.FindByEmailAsync(email);
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

finally, register it via `AuthEndpointsBuilder.AddAuthenticator<>()`:

```cs
var builder = services.AddAuthEndpoints<string, IdentityUser>();
builder.AddAuthenticator<MyAuthenticator>();
```
