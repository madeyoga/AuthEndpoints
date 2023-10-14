using AuthEndpoints.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Users;
public class UserEndpointsOptionsValidator : IValidateOptions<UserEndpointsOptions>
{
    private readonly ILogger _logger;

    public UserEndpointsOptionsValidator(ILogger logger)
    {
        _logger = logger;
    }

    public ValidateOptionsResult Validate(string name, UserEndpointsOptions options)
    {
        if (options.EmailConfirmationUrl == null)
        {
            _logger.LogWarning("EmailConfirmationUrl is null. Some functionality may not work properly.");
        }
        if (options.PasswordResetUrl == null)
        {
            _logger.LogWarning("PasswordResetUrl is null. Some functionality may not work properly.");
        }

        return ValidateOptionsResult.Success;
    }
}
