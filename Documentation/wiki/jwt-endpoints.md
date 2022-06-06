# JWT Endpoints

[`JwtController<TUserKey, TUser>`](/api/AuthEndpoints.Controllers.html#baseendpointscontroller-tuserkey-tuser)

## JWT Create

Use this endpoint to obtain jwt.

__Default URL__: `/jwt/create`

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
          <li>username</li>
          <li>password</li>
        </ul>
      </td>
      <td>
        HTTP_200_OK
        <ul>
          <li>accessToken</li>
          <li>refreshToken</li>
        </ul>
        HTTP_401_UNAUTHORIZED
      </td>
    </tr>
  </tbody>
</table>

## JWT Refresh

Use this endpoint to refresh jwt.

__Default URL__: `/jwt/refresh`

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
          <li>refreshToken</li>
        </ul>
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

## JWT Verify

Use this endpoints to verify access jwt.

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
      <td>GET</td>
      <td>
        -
      </td>
      <td>
        <ul>
          <li>HTTP_200_OK</li>
          <li>HTTP_401_UNAUTHORIZED</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>
