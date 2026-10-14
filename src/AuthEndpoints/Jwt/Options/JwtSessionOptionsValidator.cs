using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Rejects a non-positive refresh lifetime and an unknown transport.
/// </summary>
public class JwtSessionOptionsValidator : IValidateOptions<JwtSessionOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, JwtSessionOptions options)
    {
        if (options.RefreshTokenLifetime <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                "JwtSessionOptions.RefreshTokenLifetime must be greater than zero.");
        }

        if (options.AbsoluteLifetime <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                "JwtSessionOptions.AbsoluteLifetime must be greater than zero.");
        }

        if (!Enum.IsDefined(options.RefreshTokenTransport))
        {
            return ValidateOptionsResult.Fail(
                "JwtSessionOptions.RefreshTokenTransport is not a known value.");
        }

        return ValidateOptionsResult.Success;
    }
}
