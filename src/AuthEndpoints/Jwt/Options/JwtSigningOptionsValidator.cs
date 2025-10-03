using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

public class JwtSigningOptionsValidator : IValidateOptions<SimpleJwtSigningOptions>
{
    public ValidateOptionsResult Validate(string? name, SimpleJwtSigningOptions options)
    {
        var signingAlgorithm = options.GetAlgorithm();
        if (string.IsNullOrWhiteSpace(signingAlgorithm))
            return ValidateOptionsResult.Fail("Algorithm must be specified.");

        if (signingAlgorithm.StartsWith("HS") && string.IsNullOrWhiteSpace(options.SymmetricKey))
            return ValidateOptionsResult.Fail("Symmetric key is required for HMAC algorithms.");

        if (signingAlgorithm.StartsWith("RS") && options.RsaKey == null && options.Certificate == null)
            return ValidateOptionsResult.Fail("RSA key or X509 certificate is required for RSA algorithms.");

        if (signingAlgorithm.StartsWith("ES") && options.EcdsaKey == null)
            return ValidateOptionsResult.Fail("ECDsa key is required for ECDSA algorithms.");

        if (signingAlgorithm.StartsWith("PS") && options.RsaKey == null)
            return ValidateOptionsResult.Fail("RSA key is required for PS algorithms.");

        return ValidateOptionsResult.Success;
    }
}
