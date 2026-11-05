# Call the password facade routes

Paths below use `Path` (default `/auth`). A host that changes `Path` uses that prefix. Management routes list the schemes `AddIdentityApiEndpoints` registered: `Identity.Application` and `Identity.Bearer`. A JWT session also lists the JWT bearer scheme `Bearer`. Cookie `POST /auth/logout` uses the default authorization policy, so its `AuthenticationSchemes` value is empty. A ReAuth cookie or an `X-AuthEndpoints-Reauth` token is a step-up proof. Management routes still require one of the schemes above.

`POST /auth/register` takes `{ "email", "password" }`. A new address and an address that already exists both return an empty `200` and leave the user signed out. An existing address also sends that owner a registration-attempt email. A password that fails the Identity rules is `400`, and that body is the same whether the address exists. `POST /auth/login` takes Identity `LoginRequest`: `email`, `password`, and optional `twoFactorCode` or `twoFactorRecoveryCode`. Login skips antiforgery. Lockout is on. The login rate limit is `AuthEndpoints.Login` (10 tokens per IP, 2 tokens restored every 10 seconds).

`useCookies` on `POST /auth/login` is ignored. Omitted or `useSessionCookies=true` sets a session cookie. `useSessionCookies=false` sets a persistent cookie. An unknown email runs a password-hash verify. A wrong authenticator code and a wrong recovery code are `401` with detail `Invalid credentials.` Both count toward lockout. A missing second factor is `401` with title `RequiresTwoFactor` and detail `Two-factor authentication is required.` The cookie login response has no `requiresTwoFactor` extension.

| Method | Path | Auth | CSRF | ReAuth | Rate limit |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/auth/register` | | | | `AccountAbuse` |
| `GET` | `/auth/confirmEmail` | | | | |
| `POST` | `/auth/resendConfirmationEmail` | Yes | Yes | | `AccountAbuse` |
| `POST` | `/auth/forgotPassword` | | | | `AccountAbuse` |
| `POST` | `/auth/resetPassword` | | | | `AccountAbuse` |
| `POST` | `/auth/login` | | | | `Login` |
| `POST` | `/auth/logout` | Yes | Yes | | |
| `GET` | `/auth/csrfToken` | | | | |
| `POST` | `/auth/confirmIdentity` | Yes | Yes | | `ConfirmIdentity` |
| `GET` | `/auth/manage/authMethods` | Yes | | | |
| `GET` | `/auth/manage/2fa` | Yes | | | |
| `POST` | `/auth/manage/2fa` | Yes | Yes | Yes | |
| `GET` | `/auth/manage/info` | Yes | | | |
| `POST` | `/auth/manage/info` | Yes | Yes | Yes | |
| `POST` | `/auth/manage/password` | Yes | Yes | Yes | `AccountAbuse` |

`GET /auth/manage/2fa` returns `isTwoFactorEnabled` and `recoveryCodesLeft`. `POST /auth/manage/2fa` changes the security stamp. It refreshes a cookie session and renews the ReAuth proof for the new stamp with the original expiry, so enabling 2FA after `{}` needs no second step-up. A ReAuth cookie is reissued. A token sent in `X-AuthEndpoints-Reauth` comes back renewed in the `X-AuthEndpoints-Reauth` response header. The old token then gets `403`. A cross-origin browser client needs `WithExposedHeaders("X-AuthEndpoints-Reauth")` in its CORS policy to read it.

`POST /auth/manage/password` sets a first password. It returns `404` when password sign-in is not mapped, and `400` when the account already has a password. Change an existing password with `POST /auth/manage/info`.

A JWT session uses the same register, recovery, confirm-email, and management routes. It maps `POST /auth/create`, `POST /auth/refresh`, `GET /auth/verify`, and `POST /auth/logout` in place of `POST /auth/login`. Cookie refresh also maps `GET /auth/csrfToken`. Body refresh omits that route. `POST /auth/create` and `POST /auth/refresh` use `AuthEndpoints.Login`.

When `Passkeys.ServerDomain` is set, the same prefix also maps the passkey routes in [passkeys.md](passkeys.md) and `POST /auth/confirmIdentity/passkeyOptions`. `POST /auth/confirmIdentity/emailCode/send` stays unmapped. Email-code send stays unregistered.

`AccountAbuse` is 10 requests per minute per IP. `ConfirmIdentity` is 20 requests per minute per IP. A rejected request is `429`.

Every route: [Endpoint reference](https://authendpoints.harten.id/modules/endpoints).
