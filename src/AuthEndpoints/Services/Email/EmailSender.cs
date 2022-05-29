using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthEndpoints.Services;

public class EmailSender : IEmailSender
{
    private readonly EmailOptions options;

    public EmailSender(IOptions<AuthEndpointsOptions> options)
    {
        this.options = options.Value.EmailOptions!;
    }

    public void SendEmail(MimeMessage message)
    {
        using var client = new SmtpClient();

        client.Connect(options.Host, options.Port, true);
        client.Authenticate(options.User, options.Password);

        client.Send(message);

        client.Disconnect(true);
        client.Dispose();
    }

    public async Task SendEmailAsync(MimeMessage message)
    {
        using var client = new SmtpClient();

        await client.ConnectAsync(options.Host, options.Port, true).ConfigureAwait(false);
        await client.AuthenticateAsync(options.User, options.Password).ConfigureAwait(false);

        await client.SendAsync(message).ConfigureAwait(false);

        await client.DisconnectAsync(true).ConfigureAwait(false);
        client.Dispose();
    }
}
