using AuthEndpoints.Models;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthEndpoints.Services;

public class DefaultEmailFactory : IEmailFactory
{
    private readonly EmailOptions options;

    public DefaultEmailFactory(IOptions<AuthEndpointsOptions> options)
    {
        this.options = options.Value.EmailOptions!;
    }

    private MimeMessage Create(EmailData message)
    {
        var mimeMessage = new MimeMessage();
        mimeMessage.From.Add(new MailboxAddress(options.From, options.From));
        mimeMessage.To.AddRange(message.To);
        mimeMessage.Subject = message.Subject;

        return mimeMessage;
    }

    public MimeMessage CreateConfirmationEmail(EmailData data)
    {
        var message = Create(data); 
        var body = @$"You're receiving this email because you need to finish email verification process.
Please go to the following page to verify your email:

{data.Link}

Thanks for using our site!";
        message.Body = new TextPart(MimeKit.Text.TextFormat.Text)
        {
            Text = body
        };
        return message;
    }

    public MimeMessage CreateResetPasswordEmail(EmailData data)
    {
        var message = Create(data);
        var body = @$"You're receiving this email because you requested a password reset for your user account
Please go to the following page and create a new password:

{data.Link}

Thanks for using our site!";
        message.Body = new TextPart(MimeKit.Text.TextFormat.Text)
        {
            Text = body
        };
        return message;
    }
}
