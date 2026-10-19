using AuthEndpoints.Jwt;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

internal sealed class JwtExternalBodyTransportValidator : IValidateOptions<JwtSessionOptions>
{
    internal const string Message =
        "JwtExternalLoginCompleter cannot be used when JwtSessionOptions.RefreshTokenTransport is Body. " +
        "External sign-in redirects and cannot deliver the refresh token. Use RefreshTokenTransport.Cookie.";

    public ValidateOptionsResult Validate(string? name, JwtSessionOptions options)
    {
        if (options.RefreshTokenTransport == RefreshTokenTransport.Body)
        {
            return ValidateOptionsResult.Fail(Message);
        }

        return ValidateOptionsResult.Success;
    }
}
