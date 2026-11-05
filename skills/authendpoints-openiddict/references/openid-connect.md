# OpenID Connect (optional)

Add the `openid` scope to turn on OpenID Connect. Without it, the server stays OAuth 2.0 only: `openid` is rejected and the routes below do not exist.

```csharp
options.Scopes.Add("openid");
options.Scopes.Add("email");                            // optional: releases email and email_verified
options.LogoutUrl = "https://app.example.com/sign-out"; // optional: see Logout
```

`OAuthRequests` has two nullable columns for OpenID Connect, `Nonce` and `AuthenticationMethods`. Add a migration when you upgrade, whether or not you turn OpenID Connect on.

| Route | Served by | Notes |
| --- | --- | --- |
| `GET /.well-known/openid-configuration` | OpenIddict | Discovery. The same document as the RFC 8414 metadata, with endpoint URLs from `Issuer`, never from the request `Host`. |
| `GET\|POST /connect/userinfo` | this package | `sub`, plus the email claims with the `email` scope. |
| `GET\|POST /connect/logout` | this package | RP-initiated logout. |
| `GET /.well-known/jwks` | OpenIddict | The keys that validate ID tokens. |

A request with `openid` gets an `id_token` from the token endpoint, on the code exchange and on every refresh. It is a JWT signed with the signing certificate (RS256). It lasts 20 minutes, OpenIddict's default; change it with `builder.OpenIddict.AddServer(o => o.SetIdentityTokenLifetime(…))`.

## Claims

| Claim | In | Value |
| --- | --- | --- |
| `iss` | ID token | `Issuer`. |
| `aud`, `azp` | ID token | The client id. |
| `sub` | ID token, `userinfo`, access token | From `IOAuthPrincipalFactory`: the Identity user id by default. |
| `nonce` | ID token | The authorize request's `nonce`, when it sent one. At most 512 characters. |
| `amr` | ID token | How the user signed in. See [How the user signed in](#how-the-user-signed-in). Left out when unknown. |
| `email`, `email_verified` | ID token, `userinfo` | With the `email` scope only. `email_verified` is the user's `EmailConfirmed`. |

These claims never reach access tokens. An access token still carries `sub`, plus what your principal factory sends to it.

The email claims come from the Identity user only when `sub` is that user's id. A principal factory that issues tokens for another subject (a service account the user picked, say) does not get the approving user's email attached to it. A claim the factory already set is kept as it is.

ID token claims are read when the user approves, and a refreshed ID token repeats them. `userinfo` reads the user on every call.

## How the user signed in

| Sign-in | `amr` |
| --- | --- |
| Password | `["pwd"]` |
| Password, then an authenticator or recovery code | `["pwd", "otp", "mfa"]` |
| Passkey | `["pop"]` |
| External provider (GitHub, Google, …) | `["fed"]` |
| Email code | `["otp"]` |

The values are from RFC 8176, except `fed`: RFC 8176 has none for a federated sign-in, and `fed` is the value Microsoft Entra ID uses. A recovery code counts as a one-time code. A passkey is `pop` whether or not the authenticator verified the user, because the sign-in result does not say.

`amr` is read from the sign-in cookie when `/connect/authorize` runs. AuthEndpoints password sign-in already writes `amr` to the cookie (`pwd`, or `mfa` after a second factor), and so do Identity's `PasswordSignInAsync` and `TwoFactorSignInAsync`. Passkey, external, and email-code sign-in write nothing, so with `openid` on, this package wraps the built-in `Cookie` and `IdentityBearer` sign-in completers and adds `amr` to the cookie they write. It also keeps `amr` when Identity's security stamp check rebuilds the cookie, which otherwise drops it.

`amr` is left out when the cookie does not say: a session signed in before `openid` was turned on, a sign-in completer you registered yourself, an obsolete `IPasskeySignInCompleter` or `IExternalLoginCompleter`, or a plain `SignInManager.SignInAsync`. To supply one, add an `amr` claim to the cookie principal when you sign the user in.

## userinfo

`GET` or `POST /connect/userinfo` with an access token that has the `openid` scope returns `sub`, and with the `email` scope also `email` and `email_verified`. A token without `openid` gets `403` with `insufficient_scope`. A token whose user was deleted gets `401` with `invalid_token` when it asks for the email claims.

## Logout

`GET` or `POST /connect/logout` follows OpenID Connect RP-Initiated Logout 1.0 (`id_token_hint`, `client_id`, `post_logout_redirect_uri`, `state`):

- `post_logout_redirect_uri` must exactly match a post-logout redirect URI registered for the client that `client_id` or `id_token_hint` names. Without either, or with any other URI, the request gets `400` and the browser is not redirected. A disabled or unapproved developer app gets `400` too.
- A signed-in user is signed out (the Identity application, external, and two-factor cookies) only when `id_token_hint` is an ID token that this server issued to that user. Otherwise the user stays signed in. When `LogoutUrl` is set, the browser goes there with the logout URL in `returnUrl`; your page asks the user, signs them out, and sends the browser back to `returnUrl`, which then completes. Without `LogoutUrl`, the request gets `400`. A link on another site cannot sign your users out.
- A signed-out browser goes straight to the validated `post_logout_redirect_uri`, with `state`. With no `post_logout_redirect_uri`, the endpoint answers `200` with no body.

Each client registers its own post-logout redirect URIs:

| Client | Where |
| --- | --- |
| From configuration | `PostLogoutRedirectUris` on the entry in `options.Clients`. |
| Dynamic registration | `post_logout_redirect_uris`, under the same rules as `redirect_uris`. |
| Developer apps | `postLogoutRedirectUris` in the create and edit body, under the same rules as `redirectUris`, and returned with the app. Leave it out of an edit to keep the list. With `RequireApproval`, a change sends an active app back to review. |

## Client permissions

A client gets the `openid` scope and the logout endpoint permission when `openid` is among its scopes: every configured scope by default, or the `Scopes` of a configured client. Unlike plain OpenIddict, `openid` needs that permission here, so a configured client whose `Scopes` leave it out cannot use OpenID Connect. Clients that existed before you added `openid` get the permissions at the next `SeedOAuthClientsAsync` (configured clients) or the next edit (developer apps). A dynamically registered client keeps the permissions it registered with, so it registers again.

`prompt=login` and `max_age` are refused with `invalid_request` instead of being ignored, because the server does not record when the user signed in.
