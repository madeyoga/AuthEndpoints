using Microsoft.Extensions.Options;

namespace AuthEndpoints;

internal class OptionsValidator : IValidateOptions<AuthEndpointsOptions>
{
    public ValidateOptionsResult Validate(string name, AuthEndpointsOptions options)
    {
        if (options.AccessSecret == null)
        {
            return ValidateOptionsResult.Fail("AuthEndpointsOptions.AccessTokenSecret cannot be null");
        }
        if (options.RefreshSecret == null)
        {
            return ValidateOptionsResult.Fail("AuthEndpointsOptions.RefreshTokenSecret cannot be null");
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
