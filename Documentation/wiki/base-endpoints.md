# Base Endpoints

[`BaseEndpointsController<TUserKey, TUser>`](/api/AuthEndpoints.Controllers.html#baseendpointscontroller-tuserkey-tuser)

## User Create

Use this endpoint to register new user.

__Default URL__: `/users`

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
          <li>email</li>
          <li>username</li>
          <li>password</li>
          <li>confirmPassword</li>
        </ul>
      </td>
      <td>
        <ul>
          <li>HTTP_200_OK</li>
          <li>HTTP_400_BAD_REQUEST</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

## User Verify Email

Use this endpoints to send email verification link via email. 
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


## User Verify Email Confirmation

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


## User Retrieve

Use this endpoints to retrieve the authenticated user data.

__Default URL__: `/users/me`

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
        HTTP_200_OK
        <ul>
          <li>User data</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

## Set Password

Use this endpoints to change user password.

__Default URL__: `/users/set_password`

**Authorizations** : (Jwt)

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
          <li>currentPassword</li>
          <li>newPassword</li>
          <li>confirmNewPassword</li>
        </ul>
      </td>
      <td>
        <ul>
          <li>HTTP_204_NO_CONTENT</li>
          <li>HTTP_400_BAD_REQUEST</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>


## Reset Password

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


## Reset Password Confirmation

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