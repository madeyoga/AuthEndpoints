using AuthEndpoints.Models;
using MimeKit;

namespace AuthEndpoints.Services;

public interface IEmailFactory
{
    MimeMessage CreateResetPasswordEmail(Message message);
    MimeMessage CreateConfirmationEmail(Message message);
}
