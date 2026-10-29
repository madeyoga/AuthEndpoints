---
name: authendpoints
description: "Wire AuthEndpoints in an ASP.NET Core host. AddPasswordAuth, UseAuthEndpoints, and MapPasswordAuth are the password session (cookie by default, prefix /auth). AddAuthEndpoints is the 3.x compatibility facade. Covers JWT, Identity bearer, passkeys, CSRF, ReAuth, email code, and GitHub or Google. Use when the project references the AuthEndpoints package, the user asks for Identity auth API endpoints, or the task is login, register, session, or token flows for a first-party web or mobile client."
license: MIT
---

# Wire AuthEndpoints

Use this skill when the app consumes the NuGet package.

Follow the pages at https://authendpoints.harten.id. Use the symbols on this page. Copy routes and option names from this page or from those docs.

The host needs the .NET 10 SDK (`net10.0`), ASP.NET Core Identity, and EF Core. `TUser` is a class with a public parameterless constructor. The usual user type derives from `IdentityUser<TKey>`. The key may be `string`, `Guid`, `long`, or another Identity key. `AddJwtEndpoints` throws `{TypeName} must derive from IdentityUser<TKey> to use AuthEndpoints.` when `TUser` does not derive from `IdentityUser<TKey>`. Passwordless passkey registration throws that same message in that case. A key other than `string` or `Guid` throws `Passwordless passkey registration requires IdentityUser with a string or Guid key so the user id can be chosen before CreateAsync.`

Current packages:

| Package | Version | Role |
| --- | --- | --- |
| `AuthEndpoints` | 4.0.4 | Endpoints, both facades, and external OAuth types in namespace `AuthEndpoints.External.OAuth` |
| `AuthEndpoints.OAuth.GitHub` | 4.0.1 | Registers the GitHub handler. The host maps the routes. |
| `AuthEndpoints.OAuth.Google` | 4.0.1 | Registers the Google handler. The host maps the routes. |
| `AuthEndpoints.External.OAuth` | 4.0.1 | Forwarding shim. Remove the reference. |

The provider packages depend on `AuthEndpoints` `[4.0.0, 5.0.0)`. A reference to `AuthEndpoints.External.OAuth` below 4.0.0 fails the build with `AE4000`. The 4.0.1 shim warns `AE4001`.

## Wire one password session

New hosts that want one password session call `AddPasswordAuth`, `UseAuthEndpoints`, and `MapPasswordAuth`. The session is a cookie. The prefix is `/auth`. Passkeys stay off until `Passkeys.ServerDomain` is set. Email-code sign-in and external sign-in stay unmapped. Roles use `AddPasswordAuth<TUser, TRole, TContext>` so `AddRoles<TRole>()` runs before `AddEntityFrameworkStores`. `IUserStore<TUser>` then implements `IUserRoleStore<TUser>`, `RoleManager<TRole>` resolves, and sign-in uses `UserClaimsPrincipalFactory<TUser, TRole>`. The context is `IdentityDbContext<TUser, TRole, TKey>` or the equivalent. The two-type overload registers no roles. Do not chain `.AddRoles<TRole>()` after it.

```cs
builder.Services.AddDbContext<AppDbContext>(/* your provider */);

builder.Services.AddPasswordAuth<AppUser, AppDbContext>(o =>
{
	o.Passkeys.ServerDomain = "example.com"; // omit to leave passkeys off
});

builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

var app = builder.Build();

app.UseAuthEndpoints();
app.MapPasswordAuth<AppUser>();
```

`AddPasswordAuth` registers Identity (`RequireConfirmedAccount` true, schema version 3), password sign-up, sign-in, and recovery, account management, and the cookie session. A second `AddPasswordAuth` throws. `MapPasswordAuth` without `AddPasswordAuth` throws `InvalidOperationException`.

`UseAuthEndpoints` adds authentication, authorization, rate limiting, and antiforgery, in that order. Call it after exception-handling middleware. Enable HTTPS in Production yourself. A second call is a no-op.

`MapPasswordAuth<AppUser>` maps the routes under `PasswordAuthOptions.Path`. Cookie login is `POST /auth/login` and returns an empty `200` plus `Set-Cookie: .AspNetCore.Identity.Application`. A host that also calls `AddAuthEndpoints` fails startup validation.

Tutorial: [Quick start](https://authendpoints.harten.id/getting-started/quick-start). The building-block list is on [Password auth](https://authendpoints.harten.id/modules/password-auth).

## Set password facade options

`AddPasswordAuth<TUser, TContext>(Action<PasswordAuthOptions>?)` takes these options. `Session`, `Path`, and `Passkeys.ServerDomain` are fixed by that callback. A later `Configure<PasswordAuthOptions>` that changes any of them fails validation. `EmailConfirmation` can still be set later.

| Property | Default | Meaning |
| --- | --- | --- |
| `Session` | `AuthEndpointsSession.Cookie` | `Cookie` or `Jwt`. `IdentityBearer` fails validation. |
| `Path` | `/auth` | Rooted prefix for every route this facade maps. |
| `RequireConfirmedAccount` | `true` | Applied before `ConfigureIdentity`. Unconfirmed sign-in is `401`. |
| `Passkeys.ServerDomain` | `null` | A non-whitespace value maps passkey sign-in and management. Omit it to leave passkeys off. An empty or whitespace value leaves them off and fails validation in Production. |
| `EmailConfirmation.ConfirmEmailRedirectUri` | `null` | After `GET` confirm-email, redirect here. Absolute `https` (or `http` in Development), or a rooted path. Null keeps the plain-text response. |
| `EmailConfirmation.AllowedRedirectOrigins` | empty | Required when the redirect URI is absolute. A rooted path needs no entry. |
| `Jwt` | `null` | Required `Action<SimpleJwtOptions>` when `Session` is `Jwt`. |
| `ConfigureIdentity` | `null` | `Action<IdentityOptions>` after `RequireConfirmedAccount`. |
| `RequireEmailSenderInProduction` | `true` | Production requires a real `IEmailSender<TUser>`. Identity's no-op sender fails startup. Development skips that check. |

`AddPasswordAuth` copies `EmailConfirmation` onto `AuthEndpointsOptions.EmailConfirmation`, which the confirm-email handler reads.

Set the ReAuth lifetime with `Configure<AuthEndpointsReAuthOptions>`. The default is 5 minutes. Startup rejects a lifetime under 1 minute or over 60 minutes. The cookie is a browser-session cookie. The ticket expires after `Lifetime` and stays fixed if the user keeps calling the API.

```cs
builder.Services.Configure<AuthEndpointsReAuthOptions>(o =>
{
	o.Lifetime = TimeSpan.FromMinutes(2);
});
```

Full tables: [Configuration options](https://authendpoints.harten.id/modules/configuration).

## Use a JWT session

Set `Session` to `AuthEndpointsSession.Jwt` and pass `Jwt`. Call `modelBuilder.UseRefreshToken()` and migrate. The table is `AuthEndpoints.AuthEndpointsRefreshTokens`. The absolute family lifetime adds non-null `AbsoluteExpiresAt`. Backfill existing rows from `ExpiresAt`. Recreate the table when upgrading from plaintext storage.

```cs
builder.Services.AddPasswordAuth<AppUser, AppDbContext>(o =>
{
	o.Session = AuthEndpointsSession.Jwt;
	o.Jwt = jwt =>
	{
		jwt.Issuer = "https://example.com";
		jwt.Audience = "https://example.com";
		jwt.SigningOptions.SymmetricKey = key;
	};
});
```

Password sign-in is `POST /auth/create`. The JSON body is `accessToken` and `tokenType` `Bearer`. A missing second factor is `401` with title `RequiresTwoFactor`, detail `Two-factor authentication is required.`, and extension `requiresTwoFactor` set to true. A wrong authenticator code and a wrong recovery code are `401` with detail `Invalid credentials.` Both count toward lockout. `POST /auth/logout` reads the refresh token. It has no access-token check. Refresh transport defaults to the HttpOnly cookie `AuthEndpoints.Jwt.RefreshToken` (`SameSite=Strict`, path `/`). `RefreshTokenTransport.Body` also returns `refreshToken` from create, email-code verify, passkey sign-in, and refresh. Body refresh and logout accept `{ "refreshToken" }`, skip antiforgery, and leave `GET /auth/csrfToken` unmapped. A non-JSON body on those two routes is `415`.

`AddJwtEndpoints` copies `SimpleJwtOptions.RefreshTokenTransport` onto `JwtSessionOptions` when the value is `Body`. An earlier `Configure<JwtSessionOptions>` stays when transport is left at `Cookie`. A configure registered after `AddJwtEndpoints` replaces the result.

Cookie-transport refresh returns `{ "accessToken" }` and requires the CSRF token. `GET /auth/verify` with `Authorization: Bearer` returns `204` and no refresh token.

Every refresh rotates. Reuse of an old token revokes the family. A second refresh that presents the same token after the first rotation revokes the family too. Logout and a security-stamp change revoke the family. `AbsoluteLifetime` and `RefreshTokenLifetime` both default to 14 days. Rotation leaves the absolute cap where it started.

In Production, set `Issuer` and `Audience` to values other than the defaults `Jwt` and `JwtAudience`. A symmetric key is at least 32 UTF-8 bytes. `Algorithm` `Rsa` reads `SigningOptions.RsaKey`. `Ecdsa` reads `EcdsaKey`. `X509` reads `Certificate`.

Module: [JWT](https://authendpoints.harten.id/modules/jwt).

## Call the password facade routes

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

`POST /auth/manage/password` sets a first password. It returns `404` when password sign-in is not mapped, and `400` when the account already has a password. Change an existing password with `POST /auth/manage/info`.

A JWT session uses the same register, recovery, confirm-email, and management routes. It maps `POST /auth/create`, `POST /auth/refresh`, `GET /auth/verify`, and `POST /auth/logout` in place of `POST /auth/login`. Cookie refresh also maps `GET /auth/csrfToken`. Body refresh omits that route. `POST /auth/create` and `POST /auth/refresh` use `AuthEndpoints.Login`.

When `Passkeys.ServerDomain` is set, the same prefix also maps the passkey routes below and `POST /auth/confirmIdentity/passkeyOptions`. `POST /auth/confirmIdentity/emailCode/send` stays unmapped. Email-code send stays unregistered.

`AccountAbuse` is 10 requests per minute per IP. `ConfirmIdentity` is 20 requests per minute per IP. A rejected request is `429`.

Every route: [Endpoint reference](https://authendpoints.harten.id/modules/endpoints).

## Send the CSRF token

Cookie sessions and JWT cookie refresh need antiforgery on unsafe methods that change an existing session. Login, register, forgot-password, reset-password, and both email-code routes skip antiforgery.

1. `GET /auth/csrfToken` returns `{ "csrfToken" }` and sets the antiforgery cookie. JWT body refresh has no such route. The 3.x cookie facade uses `GET /identity/csrfToken`. The 3.x JWT prefix uses `GET {Jwt.Path}/csrfToken` (default `/auth/csrfToken`) when refresh transport is `Cookie`.
2. Send that value in the antiforgery header.
3. Send cookies (`credentials: "include"`, or Axios `withCredentials`).

The library calls `AddAntiforgery()` with no header override. The ASP.NET Core header name is `RequestVerificationToken`. A host may set `AntiforgeryOptions.HeaderName`. The client uses the header the host configured. A missing or invalid token is `400` with the body `Invalid or missing CSRF token.`

The filter skips validation only when the application cookie does not authenticate the request, the request has a non-empty `Authorization: Bearer` header, and `Identity.Bearer` or the JWT bearer scheme authenticates that header. A token read from a cookie in `OnMessageReceived` still needs the CSRF token when that header is absent. An application cookie still needs the CSRF token when a bearer token is also present.

Anonymous passkey ceremonies (`POST /passkeys/requestOptions`, `POST /passkeys/register/options`, `POST /passkeys/register`, `POST /passkeys/login`) require the token for a cookie session and for JWT cookie refresh. Identity bearer and JWT body refresh omit the filter on those four routes. Pass `AuthEndpointsSession` to `MapPasskeySignInEndpoints` or `MapPasskeySignUpEndpoints` to select that rule. With no session argument, antiforgery follows `SignInCompletionOptions.Default` when `IdentityPasskeySignInCompleter<TUser>` is still the registered passkey completer. With no default, the token stays required. A custom `IPasskeySignInCompleter<TUser>` keeps the token on those parameterless maps. Signed-in passkey changes always attach the filter. The bearer-header skip above still applies.

`MapBearerAuthEndpoints` maps no `csrfToken` route.

Rules: [Antiforgery (CSRF) rules](https://authendpoints.harten.id/modules/csrf).

## Add passkeys on the password facade

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

## Keep a 3.x host on the compatibility facade

`AddAuthEndpoints` and `MapAuthEndpoints` are the 3.x facade. The methods remain in 4.x. Names, options, `AuthEndpointsSignIn`, and the `/identity`, `/account`, and `/auth` routes stay at 3.4.1. `POST /manage/password` and `POST /confirmIdentity/emailCode/send` stay unmapped. `authMethods.emailCode` stays false. Password login, JWT `POST /create`, and email-code verify ignore `SignInCompletionOptions.Default`. A host that also calls `AddPasswordAuth` fails startup validation.

```cs
builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(o =>
{
	o.Passkeys.ServerDomain = "example.com";
});

builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

app.UseAuthEndpoints();
app.MapAuthEndpoints<AppUser>();
```

`AddAuthEndpoints` returns `IdentityBuilder`. It registers Identity API endpoints, EF stores, schema version 3, antiforgery, the cookie or bearer helpers, ReAuth, and rate limits. Pass `AuthEndpointsSignIn.IdentityBearer` to map Identity `Login` in place of `LoginCookie`. Roles use the three-type overload so `AddRoles` runs before `AddEntityFrameworkStores`:

```cs
builder.Services.AddAuthEndpoints<AppUser, AppRole, AppDbContext>(o =>
{
	o.Passkeys.ServerDomain = "example.com";
});
```

`DbContext` is `IdentityDbContext<AppUser, AppRole, TKey>` or the equivalent. Call the three-type overload when this facade needs roles. A later `.AddRoles<TRole>()` on the two-type result leaves `IRoleStore` unregistered. The password facade uses `AddPasswordAuth<TUser, TRole, TContext>` for the same store order.

| Property | Default | Meaning |
| --- | --- | --- |
| `IdentityPath` | `/identity` | Management plus the configured sign-in stack. |
| `SignIn` | `Cookie` | `Cookie` or `IdentityBearer`. The `signIn` argument overwrites `o.SignIn`. |
| `PasskeyPath` | `/account` | Passkey prefix. Routes sit under `{PasskeyPath}/passkeys`. |
| `RequireConfirmedAccount` | `true` | Confirmed email required before sign-in. |
| `Passkeys.Enabled` | `true` | `false` skips passkey DI and mapping. |
| `Passkeys.ServerDomain` | `null` | Required in Production when passkeys stay enabled. |
| `Jwt.Enabled` | `false` | When true, registers and maps JWT under `Jwt.Path`. |
| `Jwt.Path` | `/auth` | JWT prefix. |
| `Jwt.Configure` | `null` | `Action<SimpleJwtOptions>`. A non-default `RefreshTokenTransport` is applied. |
| `EmailCode.Enabled` | `false` | When true, maps `POST {IdentityPath}/emailCode/send` and `POST {IdentityPath}/emailCode/verify`. |
| `EmailCode.Configure` | `null` | `Action<EmailCodeOptions>`. |
| `ReAuth.Lifetime` | 5 minutes | Applied after every `Configure<AuthEndpointsReAuthOptions>`. Set the lifetime here. |
| `ConfigureIdentity` | `null` | After the secure Identity defaults. |
| `ConfigurePasskeys` | `null` | After `ServerDomain` is applied. |
| `RequireEmailSenderInProduction` | `true` | Same Production sender check as the password facade. |

`EmailConfirmation` uses the same redirect rules as the password facade.

Cookie `POST /identity/login` is `LoginCookie`. `useCookies` is ignored. `useSessionCookies=false` is the persistent cookie. An unknown email returns without a password-hash verify. Identity bearer `POST /identity/login` returns `accessToken`, `expiresIn`, `refreshToken`, and `tokenType` when neither cookie flag is set. `useCookies=true` with `useSessionCookies` left unset or false sets a persistent application cookie. `useSessionCookies=true` sets a session cookie. Bearer refresh is `POST /identity/refresh`. That route has no rate limit. The bearer facade leaves `/csrfToken` unmapped.

JWT `POST {Jwt.Path}/create` stays on the 3.4.1 handler. That handler calls `DefaultAuthenticator`, which runs a password-hash verify for an unknown email. A wrong authenticator code is `401` with detail `Invalid two factor code.` The lockout count stays the same. A wrong recovery code is `401` with the Identity error description. A missing second factor is `401` with detail `Two-factor authentication is required.` and extension `requiresTwoFactor` set to true. Refresh, logout, and the refresh cookie match the JWT session section above.

Passkey register and login on this facade use the registered `IPasskeySignInCompleter<TUser>`. The default is `IdentityPasskeySignInCompleter<TUser>`. That completer follows `useCookies` and `useSessionCookies` on both the cookie facade and the bearer facade. Omit both flags and the response is the Identity bearer token JSON. `useCookies=true` sets a persistent application cookie. `useSessionCookies=true` sets a session cookie. `Jwt.Enabled` leaves that completer in place. A composed host passes `AuthEndpointsSession.Jwt` to `MapPasskeySignInEndpoints` when those routes should issue a Simple JWT. The cookie facade requires antiforgery on the four anonymous passkey ceremonies, and `GET /identity/csrfToken` issues that token. The Identity bearer facade omits the filter on those four routes.

`MapAuthEndpoints` always maps `POST {IdentityPath}/confirmIdentity/passkeyOptions`, including when passkeys are disabled.

Page: [3.x facade, kept for compatibility](https://authendpoints.harten.id/getting-started/compatibility-facade).

## Choose the session

| Client | Call |
| --- | --- |
| First-party browser, one password session | `AddPasswordAuth` and `MapPasswordAuth`. Leave `Session` unset. |
| Browser or native client that wants a Simple JWT | `Session = AuthEndpointsSession.Jwt` and a `Jwt` callback on `AddPasswordAuth`. |
| Native client that wants Identity bearer tokens | `AddAuthEndpoints(..., AuthEndpointsSignIn.IdentityBearer)` and `MapAuthEndpoints`. |
| Cookie and a second session | `MapSignInEndpoints` on each prefix and `MapSharedAuthEndpoints` once. |

Map one sign-in stack per prefix. Cookie and bearer both map `POST /logout`, so they need different prefixes.

## Add email code

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

## Add GitHub or Google

Neither facade maps external sign-in. Add the provider package and map the routes yourself.

```cs
builder.Services.AddExternalAuthEndpoints<AppUser>(o =>
{
	o.AutoLinkByEmail = false;
})
.AddGitHub(o =>
{
	o.ClientId = "...";
	o.ClientSecret = "...";
});

app.MapGroup("/auth/external").MapExternalAuthProvider<AppUser>("GitHub");
app.MapGroup("/auth/external").MapExternalAccountEndpoints<AppUser>();
```

`AutoLinkByEmail` defaults to false. Set it true only when a verified provider email should attach to a local account whose email is already confirmed. `RequireVerifiedEmail` defaults to true. `ErrorPath` defaults to `/auth/external/error`. Host a page there, or set another relative local path. Any other value redirects to `/`. The query is `error` and `error_description`. A client that prefers `application/json` over `text/html` gets a problem response.

`IsPersistent` defaults to true. `DefaultReturnUrl` defaults to `/`. External sign-in finishes in one redirect and skips authenticator codes and recovery codes. Pass `AuthEndpointsSession` to `MapExternalAuthProvider` or `MapExternalAuthEndpoints`. The default session is the cookie completer. `AuthEndpointsSession.Jwt` with `RefreshTokenTransport.Body` throws at map time.

GitHub sign-in uses a verified address from `GET /user/emails`. The GitHub package default callback path is `/signin-github`. The Google package default is `/signin-google`. AuthEndpoints leaves those handler paths as the packages set them. Register the paths with each provider. The login routes below are relative to the group you pass to `Map*`.

| Method | Path | Auth | CSRF | ReAuth | Rate limit |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/login/github` | | | | `Login` |
| `GET` | `/login/github/callback` | | | | |
| `GET` | `/login/google` | | | | `Login` |
| `GET` | `/login/google/callback` | | | | |
| `GET` | `/logins` | Yes | | | |
| `DELETE` | `/logins/{loginProvider}/{providerKey}` | Yes | Yes | Yes | |
| `GET` | `/link/GitHub` | Yes | | | `Login` |
| `GET` | `/link/GitHub/callback` | Yes | | | |
| `GET` | `/link/Google` | Yes | | | `Login` |
| `GET` | `/link/Google/callback` | Yes | | | |

Unlink requires a signed-in user on a registered AuthEndpoints scheme (`Identity.Application`, `Identity.Bearer`, or JWT bearer), the antiforgery filter, and a ReAuth proof for that same user. A bearer `Authorization` header skips the antiforgery check under the CSRF rule above. A missing login is `404`. Success is `204`. Removal is refused with problem title `last_signin_method` when it would delete the last sign-in method. Email code counts only when email-code sign-in is mapped and the email is confirmed.

Module: [External OAuth](https://authendpoints.harten.id/modules/external-oauth).

## Compose more than one session

Use the building blocks when the host needs email-code sign-in, external sign-in, more than one session, or a mix neither facade covers. Match each `Map*` to its `Add*`. A missing `Add*` throws `InvalidOperationException` with `Call {AddMethod} before {MapMethod}.`

`MapSignInEndpoints<TUser>(AuthEndpointsSession)` maps the per-session routes whose `Add*` is registered, plus that session's logout and refresh routes. Password login on a JWT session is `POST /create`. `MapSharedAuthEndpoints<TUser>(sharedPath)` maps the shared routes whose `Add*` is registered, and it always ensures confirm-email. Null `sharedPath` mounts them on the builder you call.

Pipeline equivalent of `UseAuthEndpoints`:

```cs
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseAntiforgery();
```

| You map | You register |
| --- | --- |
| `MapIdentityManagementApi` | `AddAuthEndpointsIdentity` (sets `RequireConfirmedAccount` true, then your callback) or `AddIdentityApiEndpoints` plus EF stores and token providers. Bare `AddIdentityApiEndpoints` leaves `RequireConfirmedAccount` false. Also `AddPasswordEndpoints` and `AddAccountManagementEndpoints`. |
| `MapCookieAuthEndpoints` | `AddCookieAuthEndpoints()` |
| `MapBearerAuthEndpoints` | `AddBearerAuthEndpoints()` |
| `MapJwtAuthEndpoints` | `AddJwtEndpoints<TUser, TContext>(...)` and `UseRefreshToken()` |
| `MapPasskeyEndpoints` | `AddPasskeyEndpoints<TUser>()` |
| `MapEmailCodeEndpoints` | `AddEmailCodeEndpoints<TUser, TContext>(...)` and `UseEmailCodes()` |
| `MapExternalAuthEndpoints` | `AddExternalAuthEndpoints<TUser>()` and `AddGitHub` or `AddGoogle` |

`MapIdentityManagementApi` maps register without login, confirm-email, account management, `POST /manage/password`, and `POST /confirmIdentity/passkeyOptions`. It maps `POST /confirmIdentity/emailCode/send` when email-code send is registered. Map it once. Pair it with one of cookie, bearer, or JWT per prefix.

`MapPasswordEndpoints()` with no arguments finishes `POST /login` through the cookie completer unless `SignInCompletionOptions.Default` names one. An explicit `PasswordLoginMode` uses `PasswordSignInAsync` and overrides that default. `MapCookieAuthEndpoints` and `MapBearerAuthEndpoints` stay on those 3.4.1 handlers.

Copy-paste hosts: [Build a custom auth stack](https://authendpoints.harten.id/composables). Pairs and routes: [Composition table](https://authendpoints.harten.id/modules/composition). Completers: [Security model](https://authendpoints.harten.id/concepts/security-model).

## Require step-up

`POST /manage/info`, `POST /manage/2fa`, signed-in passkey changes, and external unlink require a sign-in plus ReAuth for that same user, and CSRF where the route attaches the filter. `POST /confirmIdentity` accepts one proof: password, authenticator code, recovery code, passkey assertion, or `emailCode` when email-code step-up is available.

Success returns `reauthToken`. Cookie sign-in also sets the `AuthEndpoints.ReAuth` cookie. An `Authorization: Bearer` confirm returns the token only. Keep the token in memory. Send it as `X-AuthEndpoints-Reauth`. The proof carries the user's security stamp. A password change, reset, or `UpdateSecurityStampAsync` cancels it.

Pair `.RequireReauth()` with an authorization requirement that signs the user in. `ReAuthPolicy` adds no authentication schemes. A signed-in caller without step-up gets `403`.

Module: [ReAuth](https://authendpoints.harten.id/modules/reauth).

## Check production

- Serve the API over HTTPS. `UseAuthEndpoints` leaves HTTPS to the host.
- Register a real `IEmailSender<TUser>`. The password facade and `AddJwtEndpoints` register `LoggingAccountSecurityEmailSender<TUser>` when no `IAccountSecurityEmailSender<TUser>` is registered. That sender writes registration-attempt notices to the log.
- For email code, call `UseEmailCodes()`, register a real `IEmailCodeSender<TUser>` outside Development, and use `https` plus `AllowedOrigins` for an absolute magic-link URI in Production.
- Set `Passkeys.ServerDomain` when passkeys stay on. On the 3.x facade, set `Passkeys.Enabled` to false to turn them off. On the password facade, omit `ServerDomain`.
- For JWT, call `UseRefreshToken()` and set a real issuer, audience, and signing key.

Page: [Prepare for production](https://authendpoints.harten.id/concepts/production).
