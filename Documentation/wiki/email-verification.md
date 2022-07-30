## Email Verification Process

The workflow should look like this:

1. User click on a verify email button in frontend app, which will send GET request to the email verification endpoint, `/users/verify_email` by default.
2. Api server will then send an email verification link to the user via email. You should provide site in your frontend application (configured by AuthEndpointsOptions.EmailConfirmationUrl).
3. User click on the link and will get redirected to email verification page (in frontend app).
4. Frontend app will then send a POST request to the confirm email verification endpoint, `/users/verify_email_confirm` by default.
5. Api server will respond with `Status204NoContent` if succeeded.

## Configuring options

```cs
builder.Services.AddAuthEndpoints<string, IdentityUser>(options => 
{
  // will be sent to the user via email.
  options.EmailConfirmationUrl = "https://myfrontend.com/account/verify-email-confirm/{uid}/{token}"

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

### User Verify Email

Use this endpoint to send email verification link via email. 
You should provide site in your frontend application (configured by AuthEndpointsOptions.EmailConfirmationUrl) 
which will send POST request to verify email confirmation endpoint.

__Default URL__: `/users/verify_email`

**Authorizations** : (Jwt)

<table>
  <tbody>
    <tr>
      <th>Method</th>
      <th>Request</th>
      <th>Response</th>
    </tr>
    <tr>
      <td>GET</td>
      <td>
        -
      </td>
      <td>
        HTTP_204_NO_CONTENT, HTTP_401_UNAUTHORIZED
      </td>
    </tr>
  </tbody>
</table>


### User Verify Email Confirmation

Use this endpoint to finish email verification process.

__Default URL__: `/users/verify_email_confirm`

**Authorizations** : (Jwt or None)

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
        </ul>
      </td>
      <td>
        HTTP_204_NO_CONTENT, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT
      </td>
    </tr>
  </tbody>
</table>
