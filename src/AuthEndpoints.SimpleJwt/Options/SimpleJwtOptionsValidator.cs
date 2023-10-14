using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.SimpleJwt;

public class SimpleJwtOptionsValidator : IValidateOptions<SimpleJwtOptions>
{
    private readonly ILogger _logger;

    public SimpleJwtOptionsValidator(ILogger<SimpleJwtOptionsValidator> logger)
    {
        _logger = logger;
    }

    public ValidateOptionsResult Validate(string name, SimpleJwtOptions options)
    {
        if (options.AccessSigningOptions.SigningKey == null)
        {
            return ValidateOptionsResult.Fail("AccessSigningOptions.SigningKey cannot be null");
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
        
        return ValidateOptionsResult.Success;
    }
}
