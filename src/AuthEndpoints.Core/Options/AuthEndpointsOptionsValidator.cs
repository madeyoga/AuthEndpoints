using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Core.Options;

public class AuthEndpointsOptionsValidator : IValidateOptions<AuthEndpointsOptions>
{
    private readonly ILogger _logger;

    public AuthEndpointsOptionsValidator(ILogger logger)
    {
        _logger = logger;
    }

    public ValidateOptionsResult Validate(string name, AuthEndpointsOptions options)
    {
        if (options.EmailConfirmationUrl == null)
        {
            _logger.LogWarning("SimpleJwtOptions.EmailConfirmationUrl is null. Some functionality may not work properly.");
        }
        if (options.PasswordResetUrl == null)
        {
            _logger.LogWarning("SimpleJwtOptions.PasswordResetUrl is null. Some functionality may not work properly.");
        }
        if (options.EmailOptions == null)
        {
            _logger.LogWarning("Email options is null. Some functionality may not work properly.");
        }

        return ValidateOptionsResult.Success;
    }
}
