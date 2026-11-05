# Keep a 3.x host on the compatibility facade

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

JWT `POST {Jwt.Path}/create` stays on the 3.4.1 handler. That handler calls `DefaultAuthenticator`, which runs a password-hash verify for an unknown email. A wrong authenticator code is `401` with detail `Invalid two factor code.` The lockout count stays the same. A wrong recovery code is `401` with the Identity error description. A missing second factor is `401` with detail `Two-factor authentication is required.` and extension `requiresTwoFactor` set to true. Refresh, logout, and the refresh cookie match [jwt.md](jwt.md).

Passkey register and login on this facade use the registered `IPasskeySignInCompleter<TUser>`. The default is `IdentityPasskeySignInCompleter<TUser>`. That completer follows `useCookies` and `useSessionCookies` on both the cookie facade and the bearer facade. Omit both flags and the response is the Identity bearer token JSON. `useCookies=true` sets a persistent application cookie. `useSessionCookies=true` sets a session cookie. `Jwt.Enabled` leaves that completer in place. A composed host passes `AuthEndpointsSession.Jwt` to `MapPasskeySignInEndpoints` when those routes should issue a Simple JWT. The cookie facade requires antiforgery on the four anonymous passkey ceremonies, and `GET /identity/csrfToken` issues that token. The Identity bearer facade omits the filter on those four routes.

`MapAuthEndpoints` always maps `POST {IdentityPath}/confirmIdentity/passkeyOptions`, including when passkeys are disabled.

Page: [3.x facade, kept for compatibility](https://authendpoints.harten.id/getting-started/compatibility-facade).
