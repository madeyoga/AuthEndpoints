using MimeKit;

namespace AuthEndpoints.Models;

/// <summary>
/// The dto used for creating an MimeMessage object by IEmailFactory
/// </summary>
public class EmailData
{
    public List<MailboxAddress> To { get; set; }
    public string Subject { get; set; }
    public string Link { get; set; }

    public EmailData(IEnumerable<string> to, string subject, string link)
    {
        To = new List<MailboxAddress>();
        To.AddRange(to.Select(address => new MailboxAddress(address, address)));

        Subject = subject;
        Link = link;
    }
}
