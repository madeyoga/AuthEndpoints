using System.Collections.Concurrent;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

internal sealed class CapturingEmailSender : IEmailSender<TestAppUser>, IEmailCodeSender<TestAppUser>, IAccountSecurityNotifier<TestAppUser>
{
    private readonly ConcurrentQueue<CapturedMail> _sent = new();

    public IReadOnlyList<CapturedMail> Snapshot() => _sent.ToArray();

    public Task SendConfirmationLinkAsync(TestAppUser user, string email, string confirmationLink)
    {
        _sent.Enqueue(new CapturedMail(email, "confirm", confirmationLink));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetCodeAsync(TestAppUser user, string email, string resetCode)
    {
        _sent.Enqueue(new CapturedMail(email, "reset", resetCode));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(TestAppUser user, string email, string resetLink)
    {
        _sent.Enqueue(new CapturedMail(email, "reset-link", resetLink));
        return Task.CompletedTask;
    }

    private readonly ConcurrentQueue<AccountSecurityEvent<TestAppUser>> _securityEvents = new();

    /// <summary>Every account security event, including those for an account with no email.</summary>
    public IReadOnlyList<AccountSecurityEvent<TestAppUser>> SecurityEvents() => _securityEvents.ToArray();

    public Task NotifyAsync(AccountSecurityEvent<TestAppUser> securityEvent, CancellationToken cancellationToken = default)
    {
        _securityEvents.Enqueue(securityEvent);
        if (securityEvent.Email is not { } email)
        {
            return Task.CompletedTask;
        }

        _sent.Enqueue(securityEvent.Kind switch
        {
            AccountSecurityEventKind.PasswordSet => new CapturedMail(email, "security", "password-set"),
            AccountSecurityEventKind.PasswordRemoved => new CapturedMail(email, "security", "password-removed"),
            AccountSecurityEventKind.RegistrationAttempted => new CapturedMail(email, "registration-attempt", "existing-account"),
            _ => new CapturedMail(email, "security", securityEvent.Kind.ToString()),
        });
        return Task.CompletedTask;
    }

    public Task SendSignInCodeAsync(EmailCodeMessage<TestAppUser> message, CancellationToken cancellationToken = default)
    {
        _sent.Enqueue(new CapturedMail(message.Email, "email-code", message.Code)
        {
            LinkUrl = message.LinkUrl,
            Purpose = message.Purpose
        });
        return Task.CompletedTask;
    }
}

internal sealed record CapturedMail(string Email, string Kind, string Body)
{
    public string? LinkUrl { get; init; }

    public EmailCodePurpose? Purpose { get; init; }
}
