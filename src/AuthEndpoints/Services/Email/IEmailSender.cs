using MimeKit;

namespace AuthEndpoints;
public interface IEmailSender
{
    void SendEmail(MimeMessage message);
    Task SendEmailAsync(MimeMessage message);
}
