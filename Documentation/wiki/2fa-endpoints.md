# 2FA Endpoints

[`TwoStepVerificationController<TUserKey, TUser>`](/api/AuthEndpoints.Controllers.TwoStepVerificationController-2.html)

## 2FA Enable

Use this endpoint to send email with 2fa token for enabling 2fa.

__Default URL__: `/users/enable_2fa`

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
        HTTP_200_OK,
        HTTP_400_BAD_REQUEST,
        HTTP_401_UNAUTHORIZED
      </td>
    </tr>
  </tbody>
</table>

## 2FA Enable Confirm

Use this endpoint to finish enabling 2fa process.

__Default URL__: `/users/enable_2fa_confirm`

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
          <li>Email</li>
          <li>Provider</li>
          <li>Token</li>
        </ul>
      </td>
      <td>
        HTTP_200_OK,
        HTTP_400_BAD_REQUEST,
        HTTP_401_UNAUTHORIZED
      </td>
    </tr>
  </tbody>
</table>

## 2FA Login

Use this endpoints to login with 2fa process.

__Default URL__: `/users/two_step_verification_login`

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
          <li>username</li>
          <li>password</li>
          <li>provider</li>
        </ul>
      </td>
      <td>
        <ul>
          <li>HTTP_200_OK</li>
          <li>HTTP_400_BAD_REQUEST</li>
          <li>HTTP_401_UNAUTHORIZED</li>
          <li>HTTP_404_NOT_FOUND</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

## 2FA Login Confirm

Use this endpoints to login with 2fa process.

__Default URL__: `/users/two_step_verification_confirm`

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
          <li>provider</li>
          <li>token</li>
        </ul>
      </td>
      <td>
        <ul>
          <li>HTTP_200_OK</li>
          <li>HTTP_400_BAD_REQUEST</li>
          <li>HTTP_401_UNAUTHORIZED</li>
          <li>HTTP_404_NOT_FOUND</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>
