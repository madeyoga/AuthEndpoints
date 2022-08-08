using MimeKit;

namespace AuthEndpoints.Core.Services;
public interface IEmailSender
{
    void SendEmail(MimeMessage message);
    Task SendEmailAsync(MimeMessage message);
}
