# JWT with Asymmetric Key Signatures

AuthEndpoints default options for signing and validating jwts use a single security key, this is being called a symmetric encryption. 
Distributing the key in a secure way is one of the primary challenges of this encryption type, this also known as key distribution problem.
Symmetric enryption allows anyone that has access to the key that the token was encrypted with, can also decrypt it. 
To use symmetric HMAC signing and verification, the following algorithms may be used: 'HS256', 'HS384', 'HS512'.
When an HMAC algorithm is chosen, the `SecurityKey` in `AccessSigningOptions` and `RefreshSigningOptions` will be used as both the signing key and the verifying key.

On the other hand, Asymmetric Encryption is based on two keys, a public key, and a private key. 
The public key is used to validate jwt. And the private key is used to sign the jwt.
To use asymmetric RSA signing and verification, the following algorithms may be used: 'RS256', 'RS384', 'RS512'. 
When an RSA algorithm is chosen, the `SigningKey` setting must be set to an `RsaSecurityKey` that contains an RSA private key. 
Likewise, the `TokenValidationParammeters` setting must be set to an `RsaSecurityKey` that contains an RSA public key.

```cs
using var privateRsa = RSA.Create();
using var publicRsa = RSA.Create();

privateRsa.FromXmlString("<your_private_key>");
publicRsa.FromXmlString("<your_public_key>");

var accessValidationParam = new TokenValidationParameters()
{
    IssuerSigningKey = new RsaSecurityKey(publicRsa), // Verify with public key
    ValidIssuer = "https://localhost:8000",
    ValidAudience = "https://localhost:8000",
    ValidateIssuerSigningKey = true,
    ClockSkew = TimeSpan.Zero,
};

builder.Services.AddAuthEndpoints<string, MyCustomIdentityUser>(new AuthEndpointsOptions()
{
    // Use private keys for signing options
    AccessSigningOptions = new JwtSigningOptions()
    {
        SigningKey = new RsaSecurityKey(privateRsa), // Sign with private key
        Algorithm = SecurityAlgorithms.RsaSha256, // Use "RS256" algorithm
        ExpirationMinutes = 120,
    },
    RefreshSigningOptions = new JwtSigningOptions()
    {
        SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("<private_key>")),
        Algorithm = SecurityAlgorithms.HmacSha256,
        ExpirationMinutes = 120,
    },
    Audience = "https://localhost:8000",
    Issuer = "https://localhost:8000",

    // AccessValidationParameters will be used for verifying access jwts
    AccessValidationParameters = accessValidationParam
})
.AddJwtBearerAuthScheme(accessValidationParam); // Verify with public key
```
