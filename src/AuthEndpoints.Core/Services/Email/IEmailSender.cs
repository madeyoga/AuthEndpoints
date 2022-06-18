using MimeKit;

namespace AuthEndpoints.Services;
public interface IEmailSender
{
    void SendEmail(MimeMessage message);
    Task SendEmailAsync(MimeMessage message);
}
