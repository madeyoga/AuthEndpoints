# Add email code

Email-code routes stay off the password facade. Register `AddEmailCodeEndpoints<TUser, TContext>` and map `MapEmailCodeEndpoints<TUser>(session)` on the prefix that should finish the session. Call `modelBuilder.UseEmailCodes()` and migrate (`AuthEndpoints.AuthEndpointsEmailCodes`). `MapEmailCodeEndpoints` throws `NotSupportedException` when that entity is missing.

`IEmailCodeSender<TUser>` sends the code. `IEmailSender<TUser>` sends confirmation and password mail. Register `IEmailCodeSender<TUser>` outside Development when `RequireSenderOutsideDevelopment` is true (the default). In Development, a missing sender becomes `DevelopmentEmailCodeSender<TUser>`, which logs the raw code. `Code` and `LinkUrl` are raw. The send endpoint awaits `SendSignInCodeAsync`, so queue the message and return. Leave the code, token, address, and link out of logs. The log category is `AuthEndpoints.EmailCode`.

| Method | Path | Contract |
| --- | --- | --- |
| `POST` | `/emailCode/send` | `{ "email" }`. `200` with `expiresInSeconds` and `resendAfterSeconds` for a valid address, including when no mail is sent. `400` `InvalidEmail`. No CSRF. Rate limit `AuthEndpoints.EmailCode.Send` (default 5 per minute per IP). |
| `POST` | `/emailCode/verify` | `{ "email", "code" }`, or `{ "token" }` alone when the magic link is on. No CSRF. Rate limit `AuthEndpoints.Login`. |

On the 3.x facade, `EmailCode.Enabled = true` maps those two routes under `IdentityPath`. `POST /confirmIdentity/emailCode/send` stays unmapped. Verify uses `IdentityEmailCodeSignInCompleter<TUser>`. `Jwt.Enabled` leaves that completer in place. Omit both cookie flags and the response is the Identity bearer token JSON (`accessToken`, `expiresIn`, `refreshToken`, `tokenType`). `useCookies=true` sets a persistent application cookie. `useSessionCookies=true` sets a session cookie. A composed host calls `MapEmailCodeEndpoints<TUser>(AuthEndpointsSession.Jwt)` when verify should issue a Simple JWT. That session returns the JWT body for every cookie flag. Parameterless `MapEmailCodeEndpoints` honors `SignInCompletionOptions.Default`. The 3.x facade keeps the Identity completer. `AddEmailCodeSignInCompleter` is obsolete.

Failure is `401` with detail `Invalid or expired code.` A user with 2FA, `RequireTwoFactor` true (the default), and neither `twoFactorCode` nor `twoFactorRecoveryCode` gets `401` title `RequiresTwoFactor`. That response leaves the code row in place.

`AllowSignUp` and `MagicLink.Enabled` default to false. `AllowSignUp` true creates one confirmed user for an unknown address, with that email as the user name and no password. No confirmation mail is sent. `MagicLink.Enabled` requires an absolute `http` or `https` `LinkUri` with no `#`. The default link is `LinkUri + "#token=" + token`. A body that contains `token` while the magic link is off is `400` with `InvalidEmailCodeRequest`. `GET` verify is `405`.

`POST /confirmIdentity/emailCode/send` is mapped by `MapAccountManagementEndpoints` and `MapReAuthEndpoints` only when `AddEmailCodeSendEndpoints` or `AddEmailCodeEndpoints` was called. `AddEmailCodeSignInEndpoints` alone leaves it unmapped. No body. The caller is signed in. CSRF applies when management mapped it. `200` returns `expiresInSeconds` and `resendAfterSeconds`. Rate limit `AuthEndpoints.ConfirmIdentity.EmailCode` is 3 per minute per user id, or per IP when the user id is absent. `400` title `EmailCodeProofUnavailable` when the account has a password, two-factor authentication is enabled, or the account has a passkey. An external login still allows the send. `POST /confirmIdentity` accepts `{ "emailCode" }` after that send. The confirm returns `reauthToken` and leaves the current session unchanged.

`UnconfirmedAccounts` defaults to `ConfirmAndResetCredentials`. `Reject` returns `401` without confirming. Module: [Email code](https://authendpoints.harten.id/modules/email-code).
