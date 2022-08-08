## Password Reset Flow

The workflow should look like this:

1. User click on a forgot password button in frontend app.
2. Frontend app will then ask user to input the email for account.
3. User click on the submit button which will send a post request to the api server, `/users/reset_password` by default.
4. Api server will then send a reset password link to the user via email. You should provide site in your frontend application (configured by AuthEndpointsOptions.PasswordResetUrl).
5. User click on the link and will get redirected to reset password page on frontend app. 
6. User enter a new password.
7. User submit the form, which will send POST request to the password reset confirmation endpoint, `/users/reset_password_confirm` by default.
8. Api server will respond with `Status204NoContent` if succeeded.

## Configuring options

```cs
builder.Services.AddAuthEndpoints<string, IdentityUser>(options => 
{
  // will be sent to the user via email.
  options.PasswordResetUrl = "https://myfrontend.com/account/reset-password-confirm/{uid}/{token}" 

  // Make sure email options are properly setup.
  options.EmailOptions = new EmailOptions()
  {
    Host = "smtp.gmail.com",
    From = Environment.GetEnvironmentVariable("GOOGLE_MAIL_APP_USER")!,
    Port = 587,
    User = Environment.GetEnvironmentVariable("GOOGLE_MAIL_APP_USER")!,
    Password = Environment.GetEnvironmentVariable("GOOGLE_MAIL_APP_PASSWORD")!,
  };
});
```

Checkout [how to configure email options](email-config.md)


## Endpoints

### Reset Password

Use this endpoint to send email to user with password reset link.
You should provide site in your frontend application (configured by AuthEndpointsOptions.PasswordResetUrl) 
which will send POST request to reset password confirmation endpoint.

__Default URL__: `/users/reset_password`

**Authorizations** : (None)

<table>
  <tbody>
    <tr>
      <th>Method</th>
      <th>Request</th>
      <th>Response</th>
    </tr>
    <tr>
      <td>POST</td>
      <td>
        <ul>
          <li>Email</li>
        </ul>
      </td>
      <td>
        <ul>
          <li>HTTP_204_NO_CONTENT</li>
          <li>HTTP_400_BAD_REQUEST</li>
          <li>HTTP_401_UNAUTHORIZED</li>
          <li>HTTP_404_NOT_FOUND</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>


### Reset Password Confirmation

Use this endpoint to finish reset password process.

__Default URL__: `/users/reset_password_confirm`

**Authorizations** : (None)

<table>
  <tbody>
    <tr>
      <th>Method</th>
      <th>Request</th>
      <th>Response</th>
    </tr>
    <tr>
      <td>POST</td>
      <td>
        <ul>
          <li>identity</li>
          <li>token</li>
          <li>newPassword</li>
          <li>confirmNewPassword</li>
        </ul>
      </td>
      <td>
        <ul>
          <li>HTTP_204_NO_CONTENT</li>
          <li>HTTP_400_BAD_REQUEST</li>
          <li>HTTP_404_NOT_FOUND</li>
          <li>HTTP_409_CONFLICT</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>
