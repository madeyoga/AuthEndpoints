using AuthEndpoints.Models;
using MimeKit;

namespace AuthEndpoints.Services;

public interface IEmailFactory
{
    MimeMessage CreateResetPasswordEmail(EmailData data);
    MimeMessage CreateConfirmationEmail(EmailData data);
    MimeMessage CreateEnable2faEmail(EmailData data);
    MimeMessage Create2faEmail(EmailData data);
}
