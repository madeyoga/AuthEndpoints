# JWT with Asymmetric Key Signatures

The default implementation for signing and validating a jwt uses a single security key, this is being called a symmetric encryption. 
Distributing the key in a secure way is one of the primary challenges of this encryption type, this also known as key distribution problem.
Symmetric enryption allows anyone that has access to the key that the token was encrypted with, can also decrypt it. 

On the other hand, Asymmetric Encryption is based on two keys, a public key, and a private key. 
The public key is used to validate jwt. And the private key is used to sign the jwt.

For AuthEndpoints to create a jwt with Asymmetric encryption based signatures, you can use the `RsaSignedJwtFactory` class.
Register it with `AuthEndpointsBuilder.AddJwtFactory<>()`:

```cs
builder.AddJwtFactory<RsaSignedJwtFactory>();
```

Or you can also define your own jwt factory:

```cs
public class MyJwtFactory : IJwtFactory
{}

builder.AddJwtFactory<MyJwtFactory>();
```