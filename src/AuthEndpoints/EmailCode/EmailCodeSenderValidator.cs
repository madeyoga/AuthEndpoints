using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.EmailCode;

internal sealed class EmailCodeSenderValidator<TUser> : IValidateOptions<EmailCodeOptions>
    where TUser : class
{
    private readonly IHostEnvironment _environment;
    private readonly IServiceScopeFactory _scopeFactory;

    public EmailCodeSenderValidator(IHostEnvironment environment, IServiceScopeFactory scopeFactory)
    {
        _environment = environment;
        _scopeFactory = scopeFactory;
    }

    public ValidateOptionsResult Validate(string? name, EmailCodeOptions options)
    {
        if (_environment.IsDevelopment() || !options.RequireSenderInProduction)
        {
            return ValidateOptionsResult.Success;
        }

        using var scope = _scopeFactory.CreateScope();
        var sender = scope.ServiceProvider.GetService<IEmailCodeSender<TUser>>();
        if (sender is null
            || sender is DevelopmentEmailCodeSender<TUser>
            || sender is MissingEmailCodeSender<TUser>)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: A real IEmailCodeSender<TUser> must be registered outside Development " +
                "(DevelopmentEmailCodeSender is not allowed). " +
                "Example: services.AddTransient<IEmailCodeSender<AppUser>, MyEmailCodeSender>(); " +
                "Or set EmailCode.RequireSenderInProduction = false to opt out (not recommended).");
        }

        return ValidateOptionsResult.Success;
    }
}

internal sealed class MissingEmailCodeSender<TUser> : IEmailCodeSender<TUser>
    where TUser : class
{
    public Task SendSignInCodeAsync(EmailCodeMessage<TUser> message, CancellationToken cancellationToken = default)
    {
        throw new InvalidOperationException("IEmailCodeSender<TUser> is not registered.");
    }
}
