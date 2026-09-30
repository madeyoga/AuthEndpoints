using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Validates <see cref="ExternalAuthOptions"/>.
/// </summary>
public sealed class ExternalAuthOptionsValidator : IValidateOptions<ExternalAuthOptions>
{
    public ValidateOptionsResult Validate(string? name, ExternalAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.DefaultReturnUrl)
            || !ExternalAuthReturnUrl.IsRelativeLocalUrl(options.DefaultReturnUrl))
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(ExternalAuthOptions.DefaultReturnUrl)} must be a relative local path (e.g. '/').");
        }

        if (string.IsNullOrWhiteSpace(options.ErrorPath)
            || !ExternalAuthReturnUrl.IsRelativeLocalUrl(options.ErrorPath))
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(ExternalAuthOptions.ErrorPath)} must be a relative local path (e.g. '/auth/external/error').");
        }

        foreach (var origin in options.AllowedReturnUrlOrigins)
        {
            if (!ExternalAuthReturnUrl.IsAllowedOriginEntry(origin))
            {
                return ValidateOptionsResult.Fail(
                    $"{nameof(ExternalAuthOptions.AllowedReturnUrlOrigins)} entries must be absolute http(s) origins without a path, query, fragment, or userinfo.");
            }
        }

        return ValidateOptionsResult.Success;
    }
}
