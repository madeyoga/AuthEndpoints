# Token Claims
JSON web tokens (JWTs) claims are pieces of information asserted about a subject. 
In a JWT, a claim appears as a name/value pair where the name is always a string and the value can be any JSON value. 
Generally, when we talk about a claim in the context of a JWT, we are referring to the name (or key).

By default AuthEndpoints add 2 custom claims to an access token, user id and username. 
And add 1 custom claim to a refresh token, user id.
To change this, you can write a custom claims provider. Something like this will work:

```cs
public class MyClaimsProvider : IClaimsProvider<MyApplicationUser>
{
  public IList<Claim> provideAccessClaims(TUser user)
  {
    return new List<Claim>()
    {
      new Claim("id", user.Id.ToString()!),
      new Claim(ClaimTypes.Name, user.UserName),
    };
  }

  public IList<Claim> provideRefreshClaims(TUser user)
  {
    return new List<Claim>()
    {
      new Claim("id", user.Id.ToString()!),
      new Claim(ClaimTypes.Name, user.UserName),
    };
  }
}
```

then, add it using `AuthEndpointsBuilder.AddClaimsProvider<>();`

```cs
builder.AddClaimsProvider<MyClaimsProvider>();
```