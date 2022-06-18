using AuthEndpoints.Models;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthEndpoints.Services;

/// <summary>
/// Use this class to create MimeMessage for email verification request and for reset password request.
/// </summary>
public class DefaultMessageFactory : IEmailFactory
{
    private readonly EmailOptions options;

    public DefaultMessageFactory(IOptions<AuthEndpointsOptions> options)
    {
        this.options = options.Value.EmailOptions!;
    }

    private MimeMessage Create(EmailData data)
    {
        var mimeMessage = new MimeMessage();
        mimeMessage.From.Add(new MailboxAddress(options.From, options.From));
        mimeMessage.To.AddRange(data.To);
        mimeMessage.Subject = data.Subject;

        return mimeMessage;
    }

    /// <summary>
    /// Use this method to create MimeMessage for email verification request
    /// </summary>
    /// <param name="data"></param>
    /// <returns>a instance of MimeMessage</returns>
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

    /// <summary>
    /// Use this method to create MimeMessage for reset password request
    /// </summary>
    /// <param name="data"></param>
    /// <returns>a instance of MimeMessage</returns>
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

    public MimeMessage CreateEnable2faEmail(EmailData data)
    {
        var message = Create(data);
        var body = @$"You're receiving this email because you requested a 2 factor authentication for your user account
Please enter this code to finish enabling 2fa:

{data.Link}

Thanks for using our site!";
        message.Body = new TextPart(MimeKit.Text.TextFormat.Text)
        {
            Text = body
        };
        return message;
    }

    public MimeMessage Create2faEmail(EmailData data)
    {
        var message = Create(data);
        var body = @$"We noticed you’re trying to log in. Please enter this code to finish logging in:

{data.Link}

Thanks for using our site!";
        message.Body = new TextPart(MimeKit.Text.TextFormat.Text)
        {
            Text = body
        };
        return message;
    }
}
