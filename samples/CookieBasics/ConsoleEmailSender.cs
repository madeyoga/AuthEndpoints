using System.Net;
using Microsoft.AspNetCore.Identity;

namespace CookieBasics;

/// <summary>
/// Development mail sink: confirmation links and reset codes print to the console.
/// The library HTML-encodes payloads; this sender decodes them so they are copy-pasteable.
/// </summary>
internal sealed class ConsoleEmailSender : IEmailSender<IdentityUser>
{
    public Task SendConfirmationLinkAsync(IdentityUser user, string email, string confirmationLink)
    {
        Write("confirmation link", email, WebUtility.HtmlDecode(confirmationLink));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetCodeAsync(IdentityUser user, string email, string resetCode)
    {
        Write("password reset code", email, WebUtility.HtmlDecode(resetCode));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(IdentityUser user, string email, string resetLink)
    {
        Write("password reset link", email, WebUtility.HtmlDecode(resetLink));
        return Task.CompletedTask;
    }

    private static void Write(string kind, string email, string payload)
    {
        Console.WriteLine();
        Console.WriteLine($"=== AuthEndpoints {kind} for {email} ===");
        Console.WriteLine(payload);
        Console.WriteLine();
    }
}
