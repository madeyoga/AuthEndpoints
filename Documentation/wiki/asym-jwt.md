# JWT with Asymmetric Key Signatures

AuthEndpoints default implementation for signing and validating a jwt uses a single security key, this is being called a symmetric encryption. 
Distributing the key in a secure way is one of the primary challenges of this encryption type, this also known as key distribution problem.
Symmetric enryption allows anyone that has access to the key that the token was encrypted with, can also decrypt it. 

On the other hand, Asymmetric Encryption is based on two keys, a public key, and a private key. 
The public key is used to validate jwt. And the private key is used to sign the jwt.

To achive this, you need to add your private key and public key to the `AuthEndpointsOptions`:

```cs
services.AddAuthEndpoints<string, IdentityUser>(options =>
{
  // These secrets will be used for signing jwts
  options.AccessSecret = "<your_private_key>";
  options.RefreshSecret = "<your_private_key>";
  ...

  // Use public key for validation parameters.
  // These validation parameters will be used for verifying/validating jwts.
  options.AccessValidationParameters = new TokenValidationParameters()
  { ... }
  options.RefreshValidationParameters = new TokenValidationParameters()
  { ... }
});
```

For AuthEndpoints to be able to create jwts with Asymmetric algorithm based signatures, you can use the `RsaSignedJwtFactory` class.
This class uses RS256 algorithm for signing jwts.

```cs
builder.AddJwtFactory<RsaSignedJwtFactory>();
```

Or you can also define your own jwt factory:

```cs
public class MyJwtFactory : IJwtFactory
{}

builder.AddJwtFactory<MyJwtFactory>();
```