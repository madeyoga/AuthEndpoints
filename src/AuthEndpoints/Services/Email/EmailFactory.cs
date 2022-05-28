using AuthEndpoints.Models;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthEndpoints;

public class EmailFactory : IEmailFactory
{
    private readonly EmailOptions options;

    public EmailFactory(IOptions<AuthEndpointsOptions> options)
    {
        this.options = options.Value.EmailOptions!;
    }

    private MimeMessage Create(Message message)
    {
        var mimeMessage = new MimeMessage();
        mimeMessage.From.Add(new MailboxAddress(options.From, options.From));
        mimeMessage.To.AddRange(message.To);
        mimeMessage.Subject = message.Subject;
        mimeMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text)
        {
            Text = message.Body
        };

        return mimeMessage;
    }

    public MimeMessage CreateConfirmationEmail(Message message)
    {
        return Create(message);
    }

    public MimeMessage CreateResetPasswordEmail(Message message)
    {
        return Create(message);
    }
}
