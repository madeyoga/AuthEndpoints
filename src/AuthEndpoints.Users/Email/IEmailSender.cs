namespace AuthEndpoints.Users;

public interface IEmailSender
{
    Task SendEmailAsync(string email, string subject, string htmlMessage);
}

public interface IEmailSender<TUser> where TUser : class
{
    Task SendConfirmationLinkAsync(TUser user, string email, string confirmationLink);
    Task SendPasswordResetLinkAsync(TUser user, string email, string resetLink);
}
