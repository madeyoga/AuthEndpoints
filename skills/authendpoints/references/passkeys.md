# Add passkeys on the password facade

Set `Passkeys.ServerDomain`. Routes are under `/auth/passkeys`. Register and login finish in the facade session. Cookie passkey register returns `{ "credentialId" }`. When the account can sign in, the response also sets the application cookie. When it cannot, the body is still `credentialId` and the response sets no session. A JWT session that can sign in returns `accessToken` and `tokenType` `Bearer`, plus the refresh token for the configured transport. That body has no `credentialId`. Every cookie flag returns that same JWT body. When the account cannot sign in, JWT register returns an empty `200`. Passkey sign-in skips the second factor.

The default user id is `Guid.NewGuid()` (UUID v4). Register `IPasskeyUserIdFactory`, or call `AddPasskeyUserIdFactory`, to choose a different id. Passwordless register that creates a user sends the same confirmation email as password register. The completer skips a session until the account can sign in.

`POST /auth/passkeys/requestOptions` takes optional JSON `{ "email" }`. An empty or unknown email still returns `200` options. An email can reveal passkeys through `allowCredentials`. Omit `email` for discoverable login.

Rename trims the name and rejects more than 200 characters. Delete returns validation problem `LastSignInMethod` when that passkey is the only remaining sign-in method. A password, another passkey, an external login, or email code can remain. Email code counts only when email-code sign-in is mapped and the email is confirmed.

| Method | Path | Auth | CSRF | ReAuth | Rate limit |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/auth/passkeys/creationOptions` | Yes | Yes | Yes | `Passkey.ObtainOptions` |
| `POST` | `/auth/passkeys/requestOptions` | | Cookie or JWT cookie refresh | | `Passkey.ObtainOptions` |
| `POST` | `/auth/passkeys/register/options` | | Cookie or JWT cookie refresh | | `Passkey.ObtainOptions` |
| `POST` | `/auth/passkeys/register` | | Cookie or JWT cookie refresh | | `Passkey.Register` |
| `POST` | `/auth/passkeys/login` | | Cookie or JWT cookie refresh | | `Login` |
| `POST` | `/auth/passkeys/` | Yes | Yes | Yes | `Passkey.Register` |
| `GET` | `/auth/passkeys/` | Yes | | | |
| `PATCH` | `/auth/passkeys/` | Yes | Yes | Yes | |
| `DELETE` | `/auth/passkeys/{credentialIdUrl}` | Yes | Yes | Yes | |

`Passkey.ObtainOptions` is 5 requests per minute per IP. `Passkey.Register` is 3 requests per minute per IP. The ceremony state cookie is `Identity.TwoFactorUserId`. The client sends that single-use cookie from the options call to the verify call. A ReAuth credential alone leaves the signed-in passkey routes unauthorized.

`MapPasskeySignInEndpoints<TUser>(string?)` sets the confirm-email endpoint name. A string that matches a completer name still sets that endpoint name, and map time logs a warning on the `AuthEndpoints` category. Pass `AuthEndpointsSession` to select a session. `AddPasskeySignInCompleter` is obsolete. Implement `ISignInCompleter<TUser>` and register it with `AddSignInCompleter`.

An extra `MapCookieAuthEndpoints` on this facade throws `Call AddPasswordEndpoints before MapCookieAuthEndpoints.` An extra `MapIdentityManagementApi` throws `Call AddPasswordEndpoints before MapPasswordEndpoints.`

Module: [Passkeys](https://authendpoints.harten.id/modules/passkeys).
