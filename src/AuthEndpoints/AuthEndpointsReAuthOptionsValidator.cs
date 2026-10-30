using System.Threading;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

internal sealed class AuthEndpointsReAuthOptionsValidator : IValidateOptions<AuthEndpointsReAuthOptions>
{
    internal static readonly TimeSpan MinimumLifetime = TimeSpan.FromMinutes(1);
    internal static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(60);

    public ValidateOptionsResult Validate(string? name, AuthEndpointsReAuthOptions options)
    {
        var lifetime = ValidateLifetime(options.Lifetime);
        if (lifetime.Failed)
        {
            return lifetime;
        }

        var request = options.External.RequestLifetime;
        if (request < MinimumLifetime || request > TimeSpan.FromMinutes(30))
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: ReAuth.External.RequestLifetime must be between 1 and 30 minutes.");
        }

        return ValidateOptionsResult.Success;
    }

    internal static ValidateOptionsResult ValidateLifetime(TimeSpan lifetime)
    {
        if (lifetime == Timeout.InfiniteTimeSpan)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: ReAuth.Lifetime cannot be InfiniteTimeSpan.");
        }

        if (lifetime <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: ReAuth.Lifetime must be greater than zero.");
        }

        if (lifetime < MinimumLifetime)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: ReAuth.Lifetime must be at least 1 minute.");
        }

        if (lifetime > MaximumLifetime)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: ReAuth.Lifetime must be at most 60 minutes.");
        }

        return ValidateOptionsResult.Success;
    }
}
