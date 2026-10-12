using AuthEndpoints.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.EmailCode;

internal sealed class EmailCodeOptionsValidator : IValidateOptions<EmailCodeOptions>
{
    internal static readonly TimeSpan MinimumCodeLifetime = TimeSpan.FromMinutes(1);
    internal static readonly TimeSpan MaximumCodeLifetime = TimeSpan.FromMinutes(60);
    internal static readonly TimeSpan MaximumResendCooldown = TimeSpan.FromMinutes(10);
    internal const int MinimumCodeLength = 6;
    internal const int MaximumCodeLength = 10;
    internal const int MinimumAttempts = 1;
    internal const int MaximumAttempts = 10;

    private readonly IHostEnvironment _environment;

    public EmailCodeOptionsValidator(IHostEnvironment environment)
    {
        _environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, EmailCodeOptions options)
    {
        if (options.CodeLength < MinimumCodeLength || options.CodeLength > MaximumCodeLength)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.CodeLength must be from 6 through 10 digits.");
        }

        if (options.CodeLifetime < MinimumCodeLifetime || options.CodeLifetime > MaximumCodeLifetime)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.CodeLifetime must be from 1 minute through 60 minutes.");
        }

        if (options.MaxAttempts < MinimumAttempts || options.MaxAttempts > MaximumAttempts)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.MaxAttempts must be from 1 through 10.");
        }

        if (options.ResendCooldown < TimeSpan.Zero || options.ResendCooldown > MaximumResendCooldown)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.ResendCooldown must be from 0 through 10 minutes.");
        }

        if (options.MaxSendsPerEmail < 1)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.MaxSendsPerEmail must be at least 1.");
        }

        if (options.SendWindow <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.SendWindow must be greater than zero.");
        }

        if (options.SendsPerIpPerMinute < 1)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.SendsPerIpPerMinute must be at least 1.");
        }

        if (!options.MagicLink.Enabled)
        {
            return ValidateOptionsResult.Success;
        }

        if (string.IsNullOrWhiteSpace(options.MagicLink.LinkUri))
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.MagicLink.LinkUri is required when MagicLink.Enabled is true.");
        }

        return ValidateLinkUri(options.MagicLink);
    }

    private ValidateOptionsResult ValidateLinkUri(EmailCodeMagicLinkOptions magicLink)
    {
        string linkUri = magicLink.LinkUri!;
        if (linkUri.Contains('#'))
        {
            return AbsoluteLinkFailure();
        }

        if (magicLink.BuildLinkUrl is not null && IsRootedLink(linkUri))
        {
            return ValidateOptionsResult.Success;
        }

        if (!ConfirmEmailRedirect.TryGetAbsolute(linkUri, out Uri absolute))
        {
            return AbsoluteLinkFailure();
        }

        if (!_environment.IsProduction())
        {
            return ValidateOptionsResult.Success;
        }

        if (string.Equals(absolute.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.MagicLink.LinkUri must use https in Production.");
        }

        IReadOnlyList<string> allowed = ConfirmEmailRedirect.AsReadOnlyOrigins(magicLink.AllowedOrigins);
        if (allowed.Count == 0)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.MagicLink.AllowedOrigins must be set in Production.");
        }

        if (!ConfirmEmailRedirect.IsOriginAllowlisted(absolute, allowed))
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: EmailCode.MagicLink.LinkUri origin must match an AllowedOrigins entry.");
        }

        return ValidateOptionsResult.Success;
    }

    private static bool IsRootedLink(string linkUri)
    {
        return !string.IsNullOrWhiteSpace(linkUri)
            && !ConfirmEmailRedirect.IsIllegal(linkUri)
            && !ConfirmEmailRedirect.TryGetAbsolute(linkUri, out _);
    }

    private static ValidateOptionsResult AbsoluteLinkFailure()
    {
        return ValidateOptionsResult.Fail(
            "AuthEndpoints: EmailCode.MagicLink.LinkUri must be an absolute http(s) URI and must not contain '#'.");
    }
}
