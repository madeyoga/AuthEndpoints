using System.Collections.Concurrent;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

internal sealed class CapturingEmailSender : IEmailSender<TestAppUser>
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
}

internal sealed record CapturedMail(string Email, string Kind, string Body);
