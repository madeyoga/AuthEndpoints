using AuthEndpoints.Jwt;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

internal sealed class JwtExternalBodyTransportValidator : IValidateOptions<SimpleJwtOptions>
{
    internal const string Message =
        "JwtExternalLoginCompleter cannot be used when SimpleJwtOptions.RefreshTokenTransport is Body. " +
        "External sign-in redirects and cannot deliver the refresh token. Use RefreshTokenTransport.Cookie.";

    public ValidateOptionsResult Validate(string? name, SimpleJwtOptions options)
    {
        if (options.RefreshTokenTransport == RefreshTokenTransport.Body)
        {
            return ValidateOptionsResult.Fail(Message);
        }

        return ValidateOptionsResult.Success;
    }
}
