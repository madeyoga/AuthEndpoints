using AuthEndpoints.Models;
using MimeKit;

namespace AuthEndpoints;

public interface IEmailFactory
{
    MimeMessage CreateResetPasswordEmail(Message message);
    MimeMessage CreateConfirmationEmail(Message message);
}
