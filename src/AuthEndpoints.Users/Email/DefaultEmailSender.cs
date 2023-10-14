namespace AuthEndpoints.Users;

/// <summary>
/// Default <see cref="IEmailSender"/> that does nothing.
/// </summary>
public sealed class DefaultEmailSender : IEmailSender
{ 
    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        return Task.CompletedTask;
    }
}

public sealed class DefaultEmailSender<TUser> : IEmailSender<TUser>
    where TUser : class
{
    private readonly IEmailSender emailSender;

    public DefaultEmailSender(IEmailSender emailSender)
    {
        this.emailSender = emailSender;
    }

    public Task SendConfirmationLinkAsync(TUser user, string email, string confirmationLink)
    {
        var htmlMessage = @$"
You're receiving this email because you need to finish email verification process.
Please go to the following page to verify your email:

<a href='{confirmationLink}'>{confirmationLink}</a>";
        return emailSender.SendEmailAsync(email, "Email Confirmation", htmlMessage);
    }

    public Task SendPasswordResetLinkAsync(TUser user, string email, string resetLink)
    {
        var htmlMessage = @$"You're receiving this email because you requested a password reset for your user account
Please go to the following page and create a new password:

<a href='{resetLink}'>{resetLink}</a>";
        return emailSender.SendEmailAsync(email, "Reset Password", htmlMessage);
    }
}
