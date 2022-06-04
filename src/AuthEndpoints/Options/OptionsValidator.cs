using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

public class OptionsValidator : IValidateOptions<AuthEndpointsOptions>
{
    private readonly ILogger _logger;

    public OptionsValidator(ILogger<OptionsValidator> logger)
    {
        _logger = logger;
    }

    public ValidateOptionsResult Validate(string name, AuthEndpointsOptions options)
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
            return ValidateOptionsResult.Fail("AuthEndpointsOptions.Issuer cannot be null");
        }
        if (options.Audience == null)
        {
            return ValidateOptionsResult.Fail("AuthEndpointsOptions.Audience cannot be null");
        }
        if (options.AccessValidationParameters == null)
        {
            return ValidateOptionsResult.Fail("Access token ValidationParameters cannot be null");
        }
        if (options.RefreshValidationParameters == null)
        {
            return ValidateOptionsResult.Fail("Refresh token ValidationParameters cannot be null");
        }
        if (options.EmailConfirmationUrl == null)
        {
            _logger.LogWarning("AuthEndpointsOptions.EmailConfirmationUrl is null. Some functionality may not work properly.");
        }
        if (options.PasswordResetUrl == null)
        {
            _logger.LogWarning("AuthEndpointsOptions.PasswordResetUrl is null. Some functionality may not work properly.");
        }
        if (options.EmailOptions == null)
        {
            _logger.LogWarning("Email options is null. Some functionality may not work properly.");
        }
        return ValidateOptionsResult.Success;
    }
}
