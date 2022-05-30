using AuthEndpoints.Models;
using MimeKit;

namespace AuthEndpoints.Services;

public interface IEmailFactory
{
    MimeMessage CreateResetPasswordEmail(EmailData message);
    MimeMessage CreateConfirmationEmail(EmailData message);
}
