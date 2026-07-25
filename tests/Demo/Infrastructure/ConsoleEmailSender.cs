using Demo.Models;
using Microsoft.AspNetCore.Identity;

namespace Demo.Infrastructure;

/// <summary>Development-only email sender that writes to the console.</summary>
internal sealed class ConsoleEmailSender : IEmailSender<AppUser>
{
    public Task SendConfirmationLinkAsync(AppUser user, string email, string confirmationLink)
    {
        Console.WriteLine($"[Email] Confirmation for {email}: {confirmationLink}");
        return Task.CompletedTask;
    }

    public Task SendPasswordResetCodeAsync(AppUser user, string email, string resetCode)
    {
        Console.WriteLine($"[Email] Password reset code for {email}: {resetCode}");
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(AppUser user, string email, string resetLink)
    {
        Console.WriteLine($"[Email] Password reset link for {email}: {resetLink}");
        return Task.CompletedTask;
    }
}
