using Microsoft.Extensions.Options;

namespace AuthEndpoints;

internal class OptionsValidator : IValidateOptions<AuthEndpointsOptions>
{
    public ValidateOptionsResult Validate(string name, AuthEndpointsOptions options)
    {
        if (options.AccessSigningOptions.SigningKey == null)
        {
            return ValidateOptionsResult.Fail("AuthEndpointsOptions.AccessSigningKey cannot be null");
        }
        if (options.RefreshSigningOptions.SigningKey == null)
        {
            return ValidateOptionsResult.Fail("AuthEndpointsOptions.RefreshSigningKey cannot be null");
        }
        if (options.Issuer == null)
        {
            return ValidateOptionsResult.Fail("AuthEndpointsOptions.Issuer cannot be null");
        }
        if (options.Audience == null)
        {
            return ValidateOptionsResult.Fail("AuthEndpointsOptions.Audience cannot be null");
        }
        return ValidateOptionsResult.Success;
    }
}
