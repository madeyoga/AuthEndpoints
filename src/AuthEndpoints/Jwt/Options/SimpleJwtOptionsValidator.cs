using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

public class SimpleJwtOptionsValidator : IValidateOptions<SimpleJwtOptions>
{
    private readonly IHostEnvironment? _environment;

    public SimpleJwtOptionsValidator()
    {
    }

    public SimpleJwtOptionsValidator(IHostEnvironment environment)
    {
        _environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, SimpleJwtOptions options)
    {
        if (options.SigningOptions == null)
            return ValidateOptionsResult.Fail("Signing options must not be null.");

        var signingOptions = options.SigningOptions;

        var signingAlgorithm = signingOptions.GetAlgorithm();
        if (string.IsNullOrWhiteSpace(signingAlgorithm))
            return ValidateOptionsResult.Fail("Algorithm must be specified.");

        if (signingOptions.Algorithm == SimpleJwtSigningOptions.SigningAlgorithm.Symmetric
            || signingAlgorithm.StartsWith("HS", StringComparison.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(signingOptions.SymmetricKey))
            {
                return ValidateOptionsResult.Fail(
                    "SymmetricKey must be set explicitly for HMAC/symmetric signing. " +
                    "Configure SimpleJwtOptions.SigningOptions.SymmetricKey with a stable secret " +
                    "(do not rely on a per-process random default).");
            }

            if (Encoding.UTF8.GetByteCount(signingOptions.SymmetricKey) < 32)
            {
                return ValidateOptionsResult.Fail(
                    "SymmetricKey must be at least 256 bits (32 UTF-8 bytes) for HMAC signing.");
            }
        }

        if (signingAlgorithm.StartsWith("RS") && signingOptions.RsaKey == null && signingOptions.Certificate == null)
            return ValidateOptionsResult.Fail("RSA key or X509 certificate is required for RSA algorithms.");

        if (signingAlgorithm.StartsWith("ES") && signingOptions.EcdsaKey == null)
            return ValidateOptionsResult.Fail("ECDsa key is required for ECDSA algorithms.");

        if (signingAlgorithm.StartsWith("PS") && signingOptions.RsaKey == null)
            return ValidateOptionsResult.Fail("RSA key is required for PS algorithms.");

        if (_environment?.IsProduction() == true)
        {
            if (string.Equals(options.Issuer, "Jwt", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(options.Issuer))
            {
                return ValidateOptionsResult.Fail(
                    "SimpleJwtOptions.Issuer must be set to a non-default value in Production.");
            }

            if (string.Equals(options.Audience, "JwtAudience", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(options.Audience))
            {
                return ValidateOptionsResult.Fail(
                    "SimpleJwtOptions.Audience must be set to a non-default value in Production.");
            }
        }

        return ValidateOptionsResult.Success;
    }
}
