# Base Endpoints

[`BaseEndpointsController<TUserKey, TUser>`](/api/AuthEndpoints.Controllers.html#baseendpointscontroller-tuserkey-tuser)

## User Create

Use this endpoint to register new user.

__Default URL__: `/users`

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
