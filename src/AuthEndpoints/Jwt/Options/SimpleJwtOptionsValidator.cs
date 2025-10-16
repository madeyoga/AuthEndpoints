using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

public class SimpleJwtOptionsValidator : IValidateOptions<SimpleJwtOptions>
{
    public ValidateOptionsResult Validate(string? name, SimpleJwtOptions options)
    {
        if (options.SigningOptions == null)
            return ValidateOptionsResult.Fail("Signing options must not be null.");

        var signingOptions = options.SigningOptions;

        var signingAlgorithm = signingOptions.GetAlgorithm();
        if (string.IsNullOrWhiteSpace(signingAlgorithm))
            return ValidateOptionsResult.Fail("Algorithm must be specified.");

        if (signingAlgorithm.StartsWith("HS") && string.IsNullOrWhiteSpace(signingOptions.SymmetricKey))
            return ValidateOptionsResult.Fail("Symmetric key is required for HMAC algorithms.");

        if (signingAlgorithm.StartsWith("RS") && signingOptions.RsaKey == null && signingOptions.Certificate == null)
            return ValidateOptionsResult.Fail("RSA key or X509 certificate is required for RSA algorithms.");

        if (signingAlgorithm.StartsWith("ES") && signingOptions.EcdsaKey == null)
            return ValidateOptionsResult.Fail("ECDsa key is required for ECDSA algorithms.");

        if (signingAlgorithm.StartsWith("PS") && signingOptions.RsaKey == null)
            return ValidateOptionsResult.Fail("RSA key is required for PS algorithms.");

        return ValidateOptionsResult.Success;
    }
}
