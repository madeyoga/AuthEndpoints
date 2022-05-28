using MailKit.Net.Smtp;
using MimeKit;

namespace AuthEndpoints;

public class EmailSender : IEmailSender
{
    private readonly EmailOptions options;

    public EmailSender(EmailOptions options)
    {
        this.options = options;
    }

    public void SendEmail(MimeMessage message)
    {
        using var client = new SmtpClient();

        client.Connect(options.Host, options.Port, true);
        client.Authenticate(options.Username, options.Password);

        client.Send(message);

        client.Disconnect(true);
        client.Dispose();
    }

    public async Task SendEmailAsync(MimeMessage message)
    {
        using var client = new SmtpClient();

        await client.ConnectAsync(options.Host, options.Port, true);
        await client.AuthenticateAsync(options.Username, options.Password);

        await client.SendAsync(message);

        await client.DisconnectAsync(true);
        client.Dispose();
    }
}
