using MimeKit;

namespace AuthEndpoints.Models;

public class Message
{
    public List<MailboxAddress> To { get; set; }
    public string Subject { get; set; }
    public string Body { get; set; }

    public Message(IEnumerable<string> to, string subject, string body)
    {
        To = new List<MailboxAddress>();
        To.AddRange(to.Select(address => new MailboxAddress(address, address)));

        Subject = subject;
        Body = body;
    }
}
