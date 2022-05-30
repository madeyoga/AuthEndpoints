# Email Backend

AuthEndpoints library uses [MailKit](https://github.com/jstedfast/MimeKit) library for the creation and parsing of messages, and sending an email.

Learn more about MailKit [here](https://github.com/jstedfast/MailKit)

## Configuring Email Settings

You can configure email backend settings via `AuthEndpointsOptions`, for example:

```cs
builder.Services.AddAuthEndpoints<string, IdentityUser>(options => 
{
  ...

  // URL to your frontend email verification page. It should contain {uid} and {token}
  options.EmailConfirmationUrl = "https://myfrontend.com/account/verify-email/{uid}/{token}";

  // URL to your frontend password reset page. It should contain {uid} and {token}
  options.PasswordResetUrl = "https://myfrontend.com/account/password-reset/{uid}/{token}";

  options.EmailOptions = new EmailOptions() 
  {
    From = "your@gmail.com",
    Host = "smtp.gmail.com",
    Port = 587,
    User = "<gmail_app_user>",
    Password = "<gmail_app_password>",
  }
})
.AddJwtBearerAuthScheme(...);
```

## Custom Email Factory

You can customize the content of the email by implementing IEmailFactory, for example:

```cs
public class MyEmailFactory : IEmailFactory
{
  // returns a MimeMessage that will be sendt by the IEmailSender.
  public MimeMessage CreateConfirmationEmail(EmailData data);

  // returns a MimeMessage that will be sent by the IEmailSender.
  public MimeMessage CreateResetPasswordEmail(EmailData data);
}
```

then register it via `AuthEndpointsBuilder.AddEmailFactory`: 

```cs
builder.AddEmailFactory<MyEmailFactory>();
```

Learn more about creating a MIME messages using MimeKit [here](https://github.com/jstedfast/MimeKit#creating-a-simple-message)


## Custom Email Sender

The default implementation of `IEmailSender`, `DefaultEmailSender` uses SmtpClient to send an email.
You can write your own email sender by implementing `IEmailSender`, for example:

```cs
public class MyEmailSender : IEmailSender
{
  public void SendEmail(MimeMessage message);
  public void SendEmailAsync(MimeMessage message);
}
```

then register it via `AuthEndpointsBuilder.AddEmailSender`:

```cs
builder.AddEmailSender<MyEmailSender>();
```

Learn more about using MailKit [here](https://github.com/jstedfast/MailKit#using-mailkit)
