using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.SimpleJwt.Core;

public class OptionsValidator : IValidateOptions<SimpleJwtOptions>
{
    private readonly ILogger _logger;

    public OptionsValidator(ILogger<OptionsValidator> logger)
    {
        _logger = logger;
    }

    public ValidateOptionsResult Validate(string name, SimpleJwtOptions options)
    {
        if (options.AccessSigningOptions.SigningKey == null)
        {
            return ValidateOptionsResult.Fail("AccessSigningOptions.SigningKey cannot be null");
        }
        if (options.RefreshSigningOptions.SigningKey == null)
        {
            return ValidateOptionsResult.Fail("RefreshSigningOptions.SigningKey cannot be null");
        }
        if (options.Issuer == null)
        {
            return ValidateOptionsResult.Fail("SimpleJwtOptions.Issuer cannot be null");
        }
        if (options.Audience == null)
        {
            return ValidateOptionsResult.Fail("SimpleJwtOptions.Audience cannot be null");
        }
        if (options.AccessValidationParameters == null)
        {
            return ValidateOptionsResult.Fail("Access token ValidationParameters cannot be null");
        }
        if (options.RefreshValidationParameters == null)
        {
            return ValidateOptionsResult.Fail("Refresh token ValidationParameters cannot be null");
        }
        
        return ValidateOptionsResult.Success;
    }
}
