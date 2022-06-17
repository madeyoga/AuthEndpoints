using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace AuthEndpoints.Services;

/// <summary>
/// Use this class to send an email using smtp client configured by <see cref="EmailOptions"/>.
/// </summary>
public class DefaultEmailSender : IEmailSender
{
    private readonly EmailOptions options;

    public DefaultEmailSender(IOptions<AuthEndpointsOptions> options)
    {
        this.options = options.Value.EmailOptions!;
    }

    public void SendEmail(MimeMessage message)
    {
        using var client = new SmtpClient();

        client.Connect(options.Host, options.Port, SecureSocketOptions.StartTls);
        client.Authenticate(options.User, options.Password);

        client.Send(message);

        client.Disconnect(true);
        client.Dispose();
    }

    public async Task SendEmailAsync(MimeMessage message)
    {
        using var client = new SmtpClient();

        await client.ConnectAsync(options.Host, options.Port, SecureSocketOptions.StartTls).ConfigureAwait(false);
        await client.AuthenticateAsync(options.User, options.Password).ConfigureAwait(false);

        await client.SendAsync(message).ConfigureAwait(false);

        await client.DisconnectAsync(true).ConfigureAwait(false);
        client.Dispose();
    }
}
