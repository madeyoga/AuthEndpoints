using Microsoft.Extensions.Options;

namespace AuthEndpoints;
public class AuthEndpointsOptionsValidator : IValidateOptions<AuthEndpointsOptions>
{
    public ValidateOptionsResult Validate(string name, AuthEndpointsOptions options)
    {
        Console.WriteLine("Validating options...");
        return ValidateOptionsResult.Success;
    }
}
