using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

internal sealed class TestEmailSender : IEmailSender<TestAppUser>
{
    public List<(string Email, string Subject)> Sent { get; } = [];

    public Task SendConfirmationLinkAsync(TestAppUser user, string email, string confirmationLink)
    {
        Sent.Add((email, "confirm"));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetCodeAsync(TestAppUser user, string email, string resetCode)
    {
        Sent.Add((email, "reset"));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(TestAppUser user, string email, string resetLink)
    {
        Sent.Add((email, "reset-link"));
        return Task.CompletedTask;
    }
}
