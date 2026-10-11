# Design: passwordless email-code sign-in for AuthEndpoints

Status: design only. No code, branch, PR, or release.
Repo: `madeyoga/AuthEndpoints` at `main` `bf47e5b96f7fcf14f76961e83314e3b6d9766cc3` (2026-10-08, "Add Twitter card text and drop canonical URL fragments (#283)").
Current package: **AuthEndpoints 3.2.0** (`src/AuthEndpoints/AuthEndpoints.csproj:9`, tag `v3.2.0`, published on NuGet). The brief said 3.1.0, but 3.2.0 shipped on 2026-10-08, so this feature targets **3.3.0**.
All file:line citations are against that SHA.

---

## 0. Summary

- **What it is:** an opt-in module. `POST /identity/emailCode/send` emails a 6-digit code, and `POST /identity/emailCode/verify` exchanges the code for the same session or tokens that passkey login issues. A magic link is optional and off by default. It carries a 256-bit token to the app's own front-end page, and that page POSTs the token to the same `verify` route. No `GET` route signs anyone in.
- **Storage:** a new library-owned EF table, `AuthEndpoints.AuthEndpointsEmailCodes`. It is mapped by `modelBuilder.UseEmailCodes()`, the same pattern as `UseRefreshToken()`. The design does not use Identity's `EmailTokenProvider`, because that provider cannot do single use, per-code attempt counts, invalidation on resend, or codes for unknown emails.
- **Delivery:** a new `IEmailCodeSender<TUser>`, because Identity's `IEmailSender<TUser>` is a Microsoft interface with three fixed methods. The library generates and checks codes. The app sends the mail.
- **Security defaults:** the send response is identical for known and unknown emails and send failures are swallowed. Codes are hashed at rest, compared in constant time, single use, and expire in 10 minutes. A code allows 5 attempts, a resend supersedes it, and a security-stamp change cancels it. Each IP and each email has a send limit. Authenticator 2FA is still required when it is on. Lockout applies, a verified code confirms the email, and wrong codes count toward lockout.
- **Versioning:** 3.3.0, purely additive, and nothing breaks. Hosts that opt in add one EF migration.

---

## 1. How the existing library is built (findings)

### 1.1 Registration and mapping
- The facade has three calls. `AddAuthEndpoints<TUser, TContext>(Action<AuthEndpointsOptions>)` (`src/AuthEndpoints/AuthEndpointsServiceCollectionExtensions.cs:29`) builds a `bootstrap` options instance, registers `IValidateOptions` with `ValidateOnStart`, and calls `AddIdentityApiEndpoints<TUser>` (`:128`) and `.AddEntityFrameworkStores<TContext>().AddDefaultTokenProviders()` (`:142-144`). It then adds modules based on bootstrap flags: `AddCookieAuthEndpoints()` (`:148`), `AddPasskeyEndpoints<TUser>()` when `Passkeys.Enabled` (`:160-162`), and `AddJwtEndpoints<TUser,TContext>` when `Jwt.Enabled` (`:174-176`). It returns `IdentityBuilder`, which does not carry `TContext`.
- `UseAuthEndpoints()` runs `UseAuthentication → UseAuthorization → UseRateLimiter → UseAntiforgery` (`src/AuthEndpoints/AuthEndpointsApplicationBuilderExtensions.cs:23-27`).
- `MapAuthEndpoints<TUser>()` maps `MapIdentityManagementApi` plus cookie or bearer sign-in under `IdentityPath` (`src/AuthEndpoints/AuthEndpointsEndpointRouteBuilderExtensions.cs:39-49`). It maps passkeys under `PasskeyPath` (`:51-55`) and JWT under `Jwt.Path` (`:58-62`).
- Options are a sealed class with sub-objects per module: `Passkeys` (`src/AuthEndpoints/AuthEndpointsOptions.cs:32`, `Enabled` default true `:63`), `Jwt` (`:38`, `Enabled` default false `:92`, plus `Action<SimpleJwtOptions>? Configure` `:98`), and `ReAuth.Lifetime` with a default of 5 min (`:113`). The facade copies `ReAuth.Lifetime` into `AuthEndpointsReAuthOptions` (`AuthEndpointsServiceCollectionExtensions.cs:154-158`).
- The compose API is per module: `Add<Module>Endpoints` and `Map<Module>Endpoints<TUser>()` extensions, for example `MapPasskeyEndpoints` (`src/AuthEndpoints/Passkey/PasskeyApiEndpointRouteBuilderExtensions.cs:26`) and `MapJwtAuthEndpoints` (`src/AuthEndpoints/Jwt/JwtApiEndpointRouteBuilderExtensions.cs:16`). External OAuth returns a small builder (`src/AuthEndpoints.External.OAuth/Core/ExternalAuthBuilder.cs:8`, `AddCompleter<T>()` `:23`).
- Route naming is camelCase segments: `/confirmEmail`, `/resendConfirmationEmail`, `/forgotPassword`, `/resetPassword` (`src/AuthEndpoints/Identity/IdentityApiEndpointRouteBuilderExtensions.cs:31-59`), plus `/confirmIdentity/passkeyOptions` and `/passkeys/register/options`.

### 1.2 Sign-in flows
- Password login with cookie or Identity bearer uses `PasswordSignInAsync(..., lockoutOnFailure: true)` (`src/AuthEndpoints/Identity/IdentityApiEndpoints.cs:82`, `:113`). 2FA is handled in the same request: `TwoFactorCode` goes to `TwoFactorAuthenticatorSignInAsync` (`:88`, `:119`), and `TwoFactorRecoveryCode` goes to `TwoFactorRecoveryCodeSignInAsync` (`:92`, `:123`). Failures return `401` problem details with title `RequiresTwoFactor` or `Unauthorized`/`Invalid credentials.` (`:542-556`).
- JWT `/create` checks 2FA by hand with `VerifyTwoFactorTokenAsync(AuthenticatorTokenProvider)` or `RedeemTwoFactorRecoveryCodeAsync` (`src/AuthEndpoints/Jwt/JwtEndpoints.cs:50-80`).
- Passkey login and register finish through `IPasskeySignInCompleter<TUser>` (`src/AuthEndpoints/Passkey/IPasskeySignInCompleter.cs:10`). The default `IdentityPasskeySignInCompleter` checks `IsLockedOutAsync` and `CanSignInAsync` (`src/AuthEndpoints/Passkey/IdentityPasskeySignInCompleter.cs:27-28`). It then chooses the cookie or bearer scheme from `useCookies`/`useSessionCookies` (`:74`) and calls `SignInAsync` (`:38`). `JwtPasskeySignInCompleter` issues an access token plus a refresh cookie (`src/AuthEndpoints/Jwt/JwtPasskeySignInCompleter.cs:45-75`). The default is registered with `TryAddScoped` (`src/AuthEndpoints/Passkey/ServiceCollectionExtensions.cs:68`) and replaced with `AddPasskeySignInCompleter<TUser,TCompleter>` (`:76`).
- Passwordless passkey register creates a user without a password (`src/AuthEndpoints/Passkey/PasskeyEndpoints.cs:297`) and sends the normal confirmation email (`:313`).
- Passkey and OAuth sign-in **skip 2FA by design**, as the docs say (`Documentation/content/5.concepts/4.security-model.md:35`).

### 1.3 Two-factor and token providers
- `AddDefaultTokenProviders()` (`AuthEndpointsServiceCollectionExtensions.cs:144`) registers Identity's `Default` (DataProtector), `Email`, `Phone`, and `Authenticator` providers. **An email token provider exists in Identity (`EmailTokenProvider<TUser>`, a TOTP over the security stamp), but no AuthEndpoints route exposes it.** The docs list "Sign-in with a magic link or an emailed one-time code" and "Two-factor codes by SMS or email" as unsupported (`Documentation/content/2.guides/03.sign-in.md:182-183`).
- The only 2FA that is exposed is authenticator (TOTP) plus recovery codes (`IdentityApiEndpoints.cs:364-441`, `/manage/2fa`).
- Token providers are used for confirm and change email, which call `GenerateEmailConfirmationTokenAsync`/`GenerateChangeEmailTokenAsync` and Base64Url the result (`IdentityApiEndpoints.cs:518-521`). Password reset uses `GeneratePasswordResetTokenAsync` (`:307`).

### 1.4 Email sender
- The library uses Identity's `IEmailSender<TUser>` directly: `SendConfirmationLinkAsync` (`IdentityApiEndpoints.cs:539`) and `SendPasswordResetCodeAsync` (`:311`), both with HTML-encoded values. That interface is fixed at three methods, so it can't take a new "sign-in code" message.
- In Production, a startup validator rejects a missing or no-op sender (`src/AuthEndpoints/AuthEndpointsOptionsValidator.cs:99-140`, `IsFrameworkEmailSender` `:134`). `RequireEmailSenderInProduction` turns it off (`AuthEndpointsOptions.cs:56`).

### 1.5 Enumeration
- Register returns `200` for a duplicate email (`IdentityApiEndpoints.cs:59-64`). `forgotPassword` always returns `200` and only mails confirmed users (`:299-317`). Passkey register options come back for any email.

### 1.6 Cookie and bearer handling, plus CSRF
- `useCookies`/`useSessionCookies` choose between `IdentityConstants.ApplicationScheme` and `BearerScheme` (`IdentityApiEndpoints.cs:78-80`). The passkey completer uses the same rules.
- `RequireAntiforgery()` is an endpoint filter (`src/AuthEndpoints/Identity/AntiforgeryExtensions.cs:21-26`). It skips the check only for an authenticated `Authorization: Bearer` caller without an app cookie (`:70-91`). **Login, register, forgotPassword, and resetPassword have no CSRF check** (`security-model.md:23`). `/csrfToken` is mapped only by the cookie sign-in module (`IdentityApiEndpointRouteBuilderExtensions.cs:130`), not by the bearer module.

### 1.7 Rate limiting
- Policies use ASP.NET Core `AddRateLimiter`, are partitioned by `RemoteIpAddress` only, and are registered once through marker singletons (`src/AuthEndpoints/Identity/ServiceCollectionExtensions.cs:54-140`). `Login` is a token bucket (10 tokens, 2 every 10 s, `:69-76`). `AccountAbuse` allows 10/min (`:100-105`) and `ConfirmIdentity` allows 20/min (`:129-134`). Passkey policies allow 5/min and 3/min (`src/AuthEndpoints/Passkey/ServiceCollectionExtensions.cs:34-55`). The constants are in `src/AuthEndpoints/Identity/AuthEndpointsConstants.cs:11-15`.
- **The limiter is in memory and keyed by IP only.** No existing limit is keyed by email, and none is shared across instances.

### 1.8 ReAuth (step-up)
- `POST /confirmIdentity` accepts exactly one of Password, TwoFactorCode, TwoFactorRecoveryCode, or CredentialJson (`src/AuthEndpoints/ReAuth/ReAuthEndpoints.cs:68-78`). It issues a ReAuth cookie and a `reauthToken` that last `ReAuth.Lifetime` (`:135-152`). Proof claims carry the security stamp (`:183-218`). `ReauthenticatedHandler` rejects a proof whose stamp no longer matches (`src/AuthEndpoints/ReAuth/ReauthenticatedRequirement.cs:61`, `:69-90`). Both behaviours are new in 3.2.0.
- `AuthMethodsResponse` is a **positional record** (`src/AuthEndpoints/ReAuth/Contracts/AuthMethodsResponse.cs:3-8`). Adding a member to it would change the constructor and break callers.

### 1.9 Library-owned tables, hashing, concurrency
- JWT refresh tokens live in `AuthEndpoints.AuthEndpointsRefreshTokens` (`src/AuthEndpoints/Jwt/EntityTypeConfiguration.cs:10`). The host maps them with `modelBuilder.UseRefreshToken()` (`:26`), and only `TokenHash` is stored (`src/AuthEndpoints/Jwt/Models/DefaultRefreshToken.cs:14`). The hash is SHA-256 hex (`src/AuthEndpoints/Jwt/Services/RefreshTokenService.cs:121-125`). Rotation uses a compare-and-swap through `ExecuteUpdateAsync ... Where(RevokedAt == null)` inside a transaction (`:41-69`), and `tests/AuthEndpoints.Tests/RefreshRotationConcurrencyTests.cs` covers it. Email codes reuse this exact pattern.
- `ReAuthTokenService` uses Data Protection plus `TimeProvider` (`src/AuthEndpoints/ReAuth/ReAuthTokenService.cs:19`). Email codes should use `TimeProvider` too, which `RefreshTokenService` does not (it calls `DateTime.UtcNow` at `:39`).

### 1.10 Audit events
- There are none. The library has no event or audit abstraction and no `ILogger` in endpoint code (only `ReAuthBearerAuthenticationHandler` takes `ILoggerFactory` through its base type).

---

## 2. API surface

### 2.1 Routes
These map under `IdentityPath` (default `/identity`) next to `/login`. The compose call is `MapEmailCodeEndpoints<TUser>()` on any group.

| Verb | Route | Auth | CSRF | Rate limit | Purpose |
| --- | --- | --- | --- | --- | --- |
| POST | `/emailCode/send` | anonymous | none | `AuthEndpoints.EmailCode.Send` (new, per IP) + per-email limits in store | Issue and email a code (and a link if enabled) |
| POST | `/emailCode/verify` | anonymous | none | `AuthEndpoints.Login` (existing token bucket) | Exchange code or link token for a sign-in |

The magic link does **not** get a `GET` route that signs in, for two reasons. Mail scanners such as Outlook Safe Links and Gmail pre-fetch `GET` links, which would consume or burn the token. A sign-in on `GET` is also a login-CSRF vector. The link points at the **app's front-end page**, and that page POSTs `{ "token" }` to `/emailCode/verify`. A host that wants a server-rendered landing page builds it itself, and that page also POSTs.

CSRF matches password `/login`: there is no check on send or verify. The routes do not act on an existing session. The bearer facade has no `/csrfToken` route (§1.6), so requiring CSRF would break native clients. The remaining login-CSRF risk is that an attacker posts their own valid code into a victim's browser. That is the same trade-off password login already documents (`security-model.md:23`).

### 2.2 DTOs (namespace `AuthEndpoints.EmailCode`, folder `src/AuthEndpoints/EmailCode/Contracts/`)

```csharp
public sealed class EmailCodeSendRequest
{
    public required string Email { get; init; }
}

public sealed record EmailCodeSendResponse(
    int ExpiresInSeconds,   // = CodeLifetime, constant
    int ResendAfterSeconds);// = ResendCooldown, constant

public sealed class EmailCodeVerifyRequest
{
    public string? Email { get; init; }               // with Code
    public string? Code { get; init; }                // digits only
    public string? Token { get; init; }               // magic-link token (alternative to Email+Code)
    public string? TwoFactorCode { get; init; }       // same names as Identity LoginRequest
    public string? TwoFactorRecoveryCode { get; init; }
}
```

Both send response values are constants from options, so they are identical for every email. They are not computed per address.

### 2.3 Handlers, TypedResults, ProblemDetails

`EmailCodeEndpoints<TUser>.Send` returns `Results<Ok<EmailCodeSendResponse>, ValidationProblem>`:

| Case | Result |
| --- | --- |
| Valid email (known, unknown, locked, unconfirmed, cooled down, over the per-email cap, sender threw) | `200` `{ expiresInSeconds, resendAfterSeconds }` |
| Missing or invalid email format | `400` `ValidationProblem` key `InvalidEmail` (`userManager.ErrorDescriber.InvalidEmail`, same as Register `IdentityApiEndpoints.cs:47-50`) |
| Per-IP limit | `429` empty (rate limiter) |

`EmailCodeEndpoints<TUser>.Verify` takes `?useCookies` and `?useSessionCookies` and returns `IResult` through the completer, as passkey `/login` does:

| Case | Result |
| --- | --- |
| Success, cookie | `200` empty + application cookie (`TypedResults.Empty` after `SignInAsync`) |
| Success, Identity bearer (no flags) | `200` `AccessTokenResponse` |
| Success, JWT completer | `200` `SimpleJwtTokenResponse` + refresh cookie |
| Body shape wrong: neither or both of (Email+Code) and Token, or a non-digit or wrong-length code | `400` `ValidationProblem` key `InvalidEmailCodeRequest` |
| Code is correct, the user has 2FA on, and no 2FA proof was sent | `401` problem, title `RequiresTwoFactor`, detail `Two-factor authentication is required.` (same text as `IdentityApiEndpoints.cs:546-549`). The code is **not** consumed. |
| Wrong, expired, consumed, superseded, attempts exhausted, unknown email (sign-up off), stamp changed, locked out, not allowed, wrong 2FA code | `401` problem, title `Unauthorized`, detail `Invalid or expired code.`: one response for all of these |
| Rate limit | `429` empty |

### 2.4 Mail flow (client view)
1. `POST /identity/emailCode/send { "email": "a@x.com" }` → `200 { "expiresInSeconds": 600, "resendAfterSeconds": 60 }`
2. User types the code: `POST /identity/emailCode/verify?useSessionCookies=true { "email": "a@x.com", "code": "042317" }`
3. If the response is `401 RequiresTwoFactor`, repeat the call with `"twoFactorCode": "123456"` or `"twoFactorRecoveryCode": "..."`.

---

## 3. Opt-in registration and options

### 3.1 Why not `.AddEmailCode()` on the builder
`AddAuthEndpoints` returns `IdentityBuilder`, which has no `TContext`, and the store needs `TContext`. The existing modules also opt in through option sub-objects (`o.Passkeys`, `o.Jwt`). Email codes follow `AuthEndpointsJwtOptions` exactly, with an `Enabled` flag and an `Action<T>? Configure`. Compose hosts get the usual `Add…/Map…` pair.

```csharp
// Facade
builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(o =>
{
    o.EmailCode.Enabled = true;
    o.EmailCode.Configure = ec =>
    {
        ec.CodeLength = 6;
        ec.MagicLink.Enabled = true;
        ec.MagicLink.LinkUri = "https://app.example.com/auth/email-link";
        ec.MagicLink.AllowedOrigins.Add("https://app.example.com");
    };
});
builder.Services.AddTransient<IEmailCodeSender<AppUser>, MyEmailCodeSender>();
// AppDbContext.OnModelCreating: builder.UseEmailCodes();  + migration

// Compose
builder.Services.AddEmailCodeEndpoints<AppUser, AppDbContext>(ec => { /* same options */ });
builder.Services.AddEmailCodeSignInCompleter<AppUser, JwtEmailCodeSignInCompleter<AppUser>>(); // JWT hosts
app.MapGroup("/identity").MapEmailCodeEndpoints<AppUser>();
```

Facade wiring:
- In `AddAuthEndpointsCore`, after the JWT block (`AuthEndpointsServiceCollectionExtensions.cs:174-180`), add `if (bootstrap.EmailCode.Enabled) services.AddEmailCodeEndpoints<TUser,TContext>(bootstrap.EmailCode.Configure)`.
- In `MapAuthEndpointsCore` (`AuthEndpointsEndpointRouteBuilderExtensions.cs:39-49`), add `if (options.EmailCode.Enabled) identity.MapEmailCodeEndpoints<TUser>()`.

### 3.2 `EmailCodeOptions`

| Option | Default | Valid range / rule |
| --- | --- | --- |
| `CodeLength` | `6` | 6–10 digits |
| `CodeLifetime` | `10 min` | 1–60 min |
| `MaxAttempts` | `5` per code | 1–10 |
| `ResendCooldown` | `60 s` | 0–10 min. A send inside the cooldown is silently ignored (still `200`). |
| `MaxSendsPerEmail` / `SendWindow` | `5` per `1 h` | ≥1. Over the cap is silently ignored (still `200`). |
| `SendsPerIpPerMinute` | `5` | ≥1. Feeds policy `AuthEndpoints.EmailCode.Send` (fixed window, `QueueLimit = 0`). |
| `AllowSignUp` | `false` | When true, a verified unknown email creates a user (§5, rule 14) |
| `RequireTwoFactor` | `true` | When the user has `TwoFactorEnabled`, verify also needs `TwoFactorCode` or `TwoFactorRecoveryCode` |
| `UnconfirmedAccounts` | `ConfirmAndResetCredentials` | enum `{ ConfirmAndResetCredentials, Reject }` (open decision 1) |
| `CountFailuresTowardLockout` | `true` | Wrong code or 2FA → `AccessFailedAsync` (open decision 3) |
| `MagicLink.Enabled` | `false` | |
| `MagicLink.LinkUri` | `null` | Rooted path or absolute `https` URI. Required when the link is enabled. Validated with the `ConfirmEmailRedirect` helpers (`AuthEndpointsOptionsValidator.cs:57-90`): https and an allowlisted origin in Production. |
| `MagicLink.AllowedOrigins` | empty | Same semantics as `EmailConfirmation.AllowedRedirectOrigins` (`AuthEndpointsOptions.cs:85`) |
| `MagicLink.BuildLinkUrl` | `null` | `Func<EmailCodeLinkContext, string>?` override. Default: `LinkUri + "#token=" + token`. The fragment keeps the token out of server logs and `Referer`. |
| `RequireSenderInProduction` | `true` | Startup check for a real `IEmailCodeSender<TUser>` (§6) |

The validator `EmailCodeOptionsValidator` runs with `ValidateOnStart` and checks every range above, `LinkUri` when the link is enabled, and the Production sender.

---

## 4. Storage

### 4.1 Options compared

| Need | A. Identity token provider (`EmailTokenProvider` or a custom `IUserTwoFactorTokenProvider<TUser>`) | B. New table (recommended) |
| --- | --- | --- |
| Unknown email (no user row) for enumeration-safe cooldown and `AllowSignUp` | Not possible. `GenerateAsync(purpose, manager, TUser user)` needs a user. | Keyed by email hash. `UserId` is nullable. |
| Single use | No. A TOTP code stays valid for its whole window. Forcing single use means rotating the security stamp, which logs out every session. | `ConsumedAt` compare-and-swap |
| Attempts per code | No | `Attempts` column, CAS increment |
| Invalidate the previous code on resend | No: both codes stay valid in the window | `SupersededAt` on older rows |
| Exact lifetime (10 min) | No: the Rfc6238 timestep is fixed inside Identity and its window has a tolerance, so it isn't exactly 10 min | `ExpiresAt` from `TimeProvider` |
| Per-email send limits across instances | No: the ASP.NET limiter is in memory, keyed by IP | Counted from rows, shared through the DB |
| Magic-link token | DataProtector provider works, but its long tokens can't be typed and it can't be single use | `LinkTokenHash` on the same row; consuming either consumes both |
| Migration | None | One table (opt-in hosts only) |
| Precedent | Confirm and reset email flows | `AuthEndpointsRefreshTokens` + `UseRefreshToken()` |

A custom `IUserTwoFactorTokenProvider<TUser>` backed by a table would still need the table, and it would still fail for unknown emails, so it adds an indirection with no benefit. **Recommendation: B.** The store stays `internal` in 3.3.0 (`EmailCodeStore<TContext>`, like `RefreshTokenService<TContext>`), so the public surface stays small. The library already depends on EF stores (`AuthEndpointsServiceCollectionExtensions.cs:142-143`).

### 4.2 Entity and mapping

```csharp
public class EmailCode   // AuthEndpoints.EmailCode
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public required string EmailHash { get; set; }     // hex SHA-256 of normalized email; raw email never stored
    public string? UserId { get; set; }                // null for unknown email
    public required string CodeHash { get; set; }      // see rule 3
    public string? LinkTokenHash { get; set; }         // hex SHA-256 of 32-byte token; null when link disabled
    public string? SecurityStamp { get; set; }         // user's stamp at send time
    public DateTime CreatedAt { get; set; }            // UTC
    public DateTime ExpiresAt { get; set; }
    public int Attempts { get; set; }
    public DateTime? ConsumedAt { get; set; }
    public DateTime? SupersededAt { get; set; }
}
```

- `EmailCodeConfiguration`: `ToTable("AuthEndpointsEmailCodes", "AuthEndpoints")`, a key on `Id`, an index on `(EmailHash, CreatedAt)`, and a unique filtered index on `LinkTokenHash`. Hosts call `modelBuilder.UseEmailCodes()` and add a migration.
- **Cleanup:** each `send` deletes rows for the same `EmailHash` that expired more than 24 h ago (`ExecuteDeleteAsync`). The docs recommend a periodic host job: `DELETE WHERE ExpiresAt < now - 1 day`. Rows must outlive `SendWindow` so the per-email count works.
- **Concurrency:** attempts and consumption use the `RefreshTokenService` CAS pattern (`RefreshTokenService.cs:44-53`):
  - Increment: `Where(Id == id && ConsumedAt == null && Attempts < Max).ExecuteUpdateAsync(Attempts + 1)`
  - Consume: `Where(Id == id && ConsumedAt == null && SupersededAt == null && Attempts < Max && ExpiresAt > now).ExecuteUpdateAsync(ConsumedAt = now)`. Exactly one parallel verify sees `affected == 1`.
  - Send: superseding the old rows and inserting the new one happen in one transaction.
- EF InMemory can't run `ExecuteUpdate`, so concurrency tests use Sqlite, which the test host already uses (`tests/AuthEndpoints.Tests/Program.cs:30`, `UseSqlite`).

---

## 5. Security rules (numbered, each one testable)

1. **Same send response.** For any well-formed email, `send` returns `200` with the same body and headers whether the account exists, is unknown, is locked out, is unconfirmed (and `UnconfirmedAccounts = Reject`), is in cooldown, is over the per-email cap, or the sender threw. Only a malformed email (`400`) or the IP limit (`429`) differ, and neither depends on the account.
2. **Same database work.** `send` writes a row for every well-formed email that is not suppressed by cooldown or the cap, including unknown and ineligible ones (`UserId = null`, nothing mailed). The library catches and logs sender exceptions without the code. Docs advise a queued sender so mail latency doesn't create a timing side channel. The rule is documented, but the test suite can't verify timing.
3. **Hashed at rest.** The raw code and link token are never stored or logged. `CodeHash = SHA-256(Id + ":" + code)` and `LinkTokenHash = SHA-256(token)`. *Honest limit:* a 6-digit code has 10^6 values, so a stolen row can be brute-forced offline in milliseconds. The hash prevents casual exposure in dumps and logs. The real protections are the 10-minute lifetime and single use. The 256-bit link token is fully protected by its hash.
4. **Generation.** `RandomNumberGenerator.GetInt32(0, 10^n)`, zero-padded to `CodeLength`. The link token is `RandomNumberGenerator.GetBytes(32)`, Base64Url.
5. **Constant-time compare.** The submitted code is hashed with the row id and compared with `CryptographicOperations.FixedTimeEquals`. Lookup is by `EmailHash` (newest live row) or `LinkTokenHash`, never by `CodeHash`, so the database is never a code oracle.
6. **Single use.** A successful verify consumes the row through CAS. A replay returns `401 Invalid or expired code.`, and of two parallel verifies exactly one succeeds.
7. **A resend invalidates older codes.** A new send sets `SupersededAt` on every live row for that `EmailHash`. Only the newest row can verify.
8. **Attempt cap.** Each wrong code increments `Attempts`. At `MaxAttempts` the row is dead and even the right code fails. A wrong 2FA code on a correct email code also counts.
9. **Rate limits.** The new `AuthEndpoints.EmailCode.Send` policy limits sends per IP through the ASP.NET limiter, registered once through a marker like `ServiceCollectionExtensions.cs:56-61`. `verify` uses the existing `AuthEndpoints.Login` bucket. Per-email cooldown and cap live in the store because the ASP.NET limiter can't key on the request body and isn't shared across instances. They are silent (rule 1). The docs state the worst case: 5 sends/h × 5 attempts = 25 guesses per hour against 10^6.
10. **Lockout.** If the user `IsLockedOutAsync`, `send` mails nothing (still `200`) and `verify` returns the generic `401` without consuming the row. With `CountFailuresTowardLockout = true`, each wrong code or wrong 2FA code for an existing user calls `AccessFailedAsync`, and success calls `ResetAccessFailedCountAsync`. This matches `lockoutOnFailure: true` everywhere else.
11. **`EmailConfirmed`.** A verified code proves control of the inbox, so it sets `EmailConfirmed = true` before the `CanSignInAsync` check. Because `RequireConfirmedAccount` defaults to true (`AuthEndpointsOptions.cs:29`), this also fixes the documented gap "a user who loses the first email cannot get another one" (`security-model.md:47`). **Pre-hijack defence:** if the account was unconfirmed and already has a password, passkeys, or external logins, someone else may have created it. With `ConfirmAndResetCredentials`, the library removes the password, passkeys, and external logins, then calls `UpdateSecurityStampAsync`. With `Reject`, unconfirmed accounts that have any credential get the generic `401`, and unconfirmed accounts with no credentials are confirmed (open decision 1).
12. **2FA step-up.** When `RequireTwoFactor` is set and `GetTwoFactorEnabledAsync(user)` is true:
    - A correct code with no 2FA proof returns `401 RequiresTwoFactor` and does not consume the row.
    - A `TwoFactorCode` is checked with `VerifyTwoFactorTokenAsync(user, Options.Tokens.AuthenticatorTokenProvider, …)`, the same call as `JwtEndpoints.cs:54` and `ReAuthEndpoints.cs:114`.
    - A `TwoFactorRecoveryCode` is checked with `RedeemTwoFactorRecoveryCodeAsync`.
    - The row is consumed only after both factors pass.
    - Email-code sign-in neither sets nor honours Identity's remember-client cookie. That's stricter than password login and keeps the flow free of the `TwoFactorUserIdScheme` cookie, which bearer clients don't have.
13. **Security stamp.** The row stores the user's stamp at send time. At verify, a different current stamp (after a password change or reset, a 2FA change, or a credential reset) consumes the row and returns `401`. Verify also checks that the user's current normalized email still hashes to `EmailHash`, so a code sent before an email change fails. A successful sign-in does **not** rotate the stamp, so other sessions are untouched. The exception is the credential reset in rule 11.
14. **`AllowSignUp`** (default `false`). When it is false, a verify for an email with no user fails with the generic `401`. When it is true, a verified unknown email creates a `TUser` with `UserName = Email = the submitted email`, `EmailConfirmed = true`, and no password, the same shape as passkey register (`PasskeyEndpoints.cs:292-297`). Sign-in then completes. If a parallel `CreateAsync` returns `DuplicateEmail`/`DuplicateUserName`, the library looks the user up again and goes through the normal 2FA and lockout checks. No confirmation email is sent, because the code is the confirmation.
15. **ReAuth and fresh sign-in.** A successful verify is a normal sign-in. It does **not** issue a ReAuth proof, so sensitive routes still need `/confirmIdentity`. Email codes are **not** accepted as a `/confirmIdentity` proof in 3.3.0, and `ConfirmIdentityRequest` and `AuthMethodsResponse` stay unchanged. Changing the positional record would break callers (§1.8). This can be added later as a separate opt-in.
16. **Magic link.** The token lives only in the URL fragment. Verify by token requires the row to be live, consumes it (which also kills the code), and applies rules 10–14. No `GET` route signs in (§2.1). The link signs in the device that opens it, which is the expected cross-device behaviour, and the docs state this.
17. **Audit.** The library has no audit API (§1.10). 3.3.0 adds `LoggerMessage` events under one category, `AuthEndpoints.EmailCode`, with fixed EventIds: `CodeIssued`, `SendSuppressed` (cooldown/cap/ineligible), `SenderFailed`, `VerifyFailed` (reason enum), `VerifyRequiresTwoFactor`, `SignedIn`, `SignedUp`, `CredentialsResetOnConfirm`. They log the user id or `EmailHash` prefix and never the code, token, or raw email. A public event hook is out of scope.

---

## 6. Email delivery

There is a new interface, because `IEmailSender<TUser>` can't be extended (§1.4):

```csharp
namespace AuthEndpoints.EmailCode;

public interface IEmailCodeSender<TUser> where TUser : class
{
    Task SendSignInCodeAsync(EmailCodeMessage<TUser> message, CancellationToken cancellationToken = default);
}

public sealed class EmailCodeMessage<TUser> where TUser : class
{
    public required string Email { get; init; }          // as submitted (trimmed)
    public TUser? User { get; init; }                    // null => sign-up (AllowSignUp only)
    public required string Code { get; init; }           // raw digits; HTML-encode when rendering
    public string? LinkUrl { get; init; }                // raw absolute URL; null when MagicLink disabled
    public required DateTimeOffset ExpiresAt { get; init; }
    public required TimeSpan Lifetime { get; init; }
    public required EmailCodePurpose Purpose { get; init; } // SignIn | SignUp
}
```

- Values are passed **raw**, not HTML-encoded. That differs from Identity's sender contract (`IdentityApiEndpoints.cs:311`, `:539`), and the XML docs say so plainly, because templates may be plain text or HTML.
- Suggested template data: product name (host-owned), the code in a large monospace block, "expires in N minutes", the link button when `LinkUrl` is set, and a line saying "If you didn't request this, ignore this email." The subject should not contain the code, so it doesn't show up in notification previews or logs. That last point is documented guidance.
- Production check: `EmailCodeSenderValidator<TUser>` mirrors `AuthEndpointsEmailSenderValidator` (`AuthEndpointsOptionsValidator.cs:99-140`). When email codes are enabled in Production it fails if no `IEmailCodeSender<TUser>` is registered or the dev sender is. The library registers no default in Production. In Development it registers `DevelopmentEmailCodeSender<TUser>` with `TryAdd`, which logs the code at `Warning` with an obvious "DEV ONLY" marker.
- Sender exceptions are caught and logged (`SenderFailed`), and the response stays `200` (rule 1).

---

## 7. Sign-in completion

- **New:** `IEmailCodeSignInCompleter<TUser>`, with `Task<IResult> CompleteAsync(HttpContext, TUser, EmailCodeSignInContext, CancellationToken)`. `EmailCodeSignInContext` carries `UseCookies`, `UseSessionCookies`, and `IsNewUser`.
- **Defaults:**
  - `IdentityEmailCodeSignInCompleter<TUser>` has the same scheme rules as `IdentityPasskeySignInCompleter` (`:74-86`): `useCookies` gives a persistent cookie, `useSessionCookies` gives a session cookie, and neither gives an Identity bearer token. It is registered with `TryAddScoped`.
  - `JwtEmailCodeSignInCompleter<TUser>` mirrors `JwtPasskeySignInCompleter`. Hosts register it with `AddEmailCodeSignInCompleter<TUser,TCompleter>()`.
  - The scheme-selection helper becomes an internal shared method, so the passkey and email-code completers can't drift apart.
- **Why a new interface:** reusing `IPasskeySignInCompleter` would mean adding a value to the public `PasskeySignInKind` enum (`PasskeySignInCompletionContext.cs`). That would put an email-code case inside custom passkey completers that switch on the enum.
- The endpoint runs lockout, `CanSignInAsync`, and 2FA **before** the completer, so completers stay thin, as `PasskeySignInGate.CompleteIfAllowedAsync` does.

---

## 8. Verify algorithm (reference order)
1. Shape check (§2.3) → `400`.
2. Load the newest live row by `EmailHash` (code path) or the row by `LinkTokenHash` (link path). If there is none, or it is expired, consumed, superseded, or out of attempts → `401`.
3. Resolve the user from `row.UserId`. If the email or stamp no longer matches (rule 13), consume the row → `401`. If `UserId` is null and `AllowSignUp` is off, increment attempts → `401`.
4. User locked out → `401` (row untouched).
5. Constant-time compare (code path). On a mismatch, CAS `Attempts+1` and call `AccessFailedAsync` → `401`.
6. 2FA (rule 12): a missing proof returns `401 RequiresTwoFactor`. A wrong proof does `Attempts+1` and `AccessFailedAsync` → `401`.
7. CAS consume. `affected == 0` → `401`.
8. Sign-up (rule 14) or the unconfirmed-account policy (rule 11).
9. `CanSignInAsync` false → `401`.
10. `ResetAccessFailedCountAsync`, then the completer.

Send algorithm: validate the format → normalize (`userManager.NormalizeEmail`) and hash → check cooldown and cap from rows (if suppressed, return `200`) → find the user and decide eligibility → in one transaction, supersede the old rows and insert the new one → if eligible, call `SendSignInCodeAsync` (catching exceptions) → `200`.

---

## 9. Docs and sample changes

New pages:
- `Documentation/content/2.guides/` **"Sign in with an emailed code"**: client flow, 2FA retry, magic-link page snippet (read `#token`, POST it, clear the fragment), and the cross-device note.
- `Documentation/content/4.modules/13.email-code.md`: options table, DI, `UseEmailCodes()` + migration, sender contract, completers.

Updates:
- `4.modules/01.endpoints.md`: two routes.
- `4.modules/09.configuration.md`: `EmailCode` section.
- `4.modules/11.errors.md`: rows from §2.3.
- `4.modules/12.rate-limits.md`: the new policy, and `verify` added under `Login`.
- `4.modules/10.csrf.md`: both routes listed as having no check.
- `2.guides/03.sign-in.md`: remove the "magic link or emailed one-time code" bullet (`:182`) and add the method to the comparison table.
- `5.concepts/4.security-model.md`: enumeration bullets; "Two-factor is a password add-on" changes to say email codes also enforce 2FA; the email-confirmation section notes the resend gap is closed for email-code hosts; the brute-force math.
- `2.guides/12.production.md`: sender check and table cleanup.
- `versions/v3.3.0.md`; `skills/authendpoints/SKILL.md`; `.cursor/skills/verify-authendpoints/features/email-code.md`; README feature list.

Sample host: the repo has no `samples/` folder, so the real host is `tests/AuthEndpoints.Tests/Program.cs`. Add an `AE_EMAIL_CODE=true` switch (beside `AE_HOST_MODE`), map `UseEmailCodes()` in `TestDbContext`, and make `CapturingEmailSender` also implement `IEmailCodeSender<TestAppUser>`. Add a quick-start snippet to `1.getting-started/3.quick-start.md`.

---

## 10. Tests

Unit tests:
1. A generated code has exactly `CodeLength` digits, keeps leading zeros, and contains only digits.
2. The link token is 32 bytes, and Base64Url round-trips.
3. Hash and compare: the right code matches, a wrong code fails, and the same code under another row id fails.
4. `EmailCodeOptionsValidator` rejects every out-of-range value, a missing `LinkUri` with the link enabled, and http or a non-allowlisted origin in Production.
5. The link URL builder puts the token in the fragment, and the `BuildLinkUrl` override is honoured.
6. Normalization: `A@X.com ` and `a@x.com` produce the same `EmailHash`.
7. The Production sender validator fails with none or with the dev sender, and passes with a real one.

Integration tests (WebApplicationFactory, Sqlite):
1. Send for known, unknown, locked, and cooled-down emails all return byte-identical status and body. Only the known one is mailed.
2. Send with a malformed email → `400 InvalidEmail`. The 6th send per minute from one IP → `429`.
3. A cooldown resend mails nothing. After the cooldown, a resend mails a new code and the old code is rejected.
4. Over `MaxSendsPerEmail`, the response is `200` and no mail is sent.
5. Verify happy path on cookie (`useSessionCookies`), Identity bearer (no flags, `AccessTokenResponse`), and JWT completer (token + refresh cookie).
6. Facade: `o.EmailCode.Enabled = false` maps no routes. `true` maps both under `IdentityPath`.
7. Wrong code ×5 kills the row, and then the correct code fails.
8. Replay after success → `401`. Two parallel verifies → exactly one `200`.
9. Expiry via a fake `TimeProvider` → `401`.
10. A password reset between send and verify → `401` (stamp). An email change between send and verify → `401`.
11. With 2FA on, a code alone → `401 RequiresTwoFactor` and the row is still usable. Code + TOTP → `200`. Code + recovery code → `200` and one recovery code is used. Code + a wrong TOTP → `401`, and attempts and AccessFailed are incremented.
12. `RequireTwoFactor = false` with 2FA on → code alone succeeds.
13. Lockout: wrong codes up to Identity's `MaxFailedAccessAttempts` lock the user. A locked user's send mails nothing and verify fails with the right code.
14. Unconfirmed account with no credentials + `RequireConfirmedAccount` → the code confirms the email and signs in.
15. Unconfirmed account with a password, `ConfirmAndResetCredentials` → signed in, `HasPasswordAsync` false, passkeys and logins removed, stamp changed. With `Reject` → `401`.
16. `AllowSignUp = false`: unknown email verify → `401`. `true` → user created confirmed with no password, then signed in. Two parallel sign-ups → one user.
17. Magic link: the token verifies. The token after the code was used → `401`. The code after the token was used → `401`. No `GET` route exists.
18. A ReAuth-protected route right after email-code sign-in → `403` until `/confirmIdentity`.
19. Sender throws → `200` and nothing is persisted as consumed.
20. Logs never contain the code, the token, or the raw email (capture logger).

---

## 11. Versioning

**3.3.0 (minor), purely additive.** Breaking-change check:
- The new public types live in `AuthEndpoints.EmailCode`. A new property on the sealed `AuthEndpointsOptions`, a new constant in `AuthEndpointsConstants`, and new extension methods are all additive.
- Everything is off by default. No route, policy, sender check, or table appears unless `EmailCode.Enabled` is set or `AddEmailCodeEndpoints` is called.
- Deliberately **not** changed, because each would break: `AuthMethodsResponse` (positional record), `ConfirmIdentityRequest` semantics and its "exactly one proof" message, `PasskeySignInKind`, and the `IEmailSender<TUser>` usage.
- Hosts that opt in must add `UseEmailCodes()` and a migration. That's a setup step, not a break.
- External.OAuth packages are unaffected.

---

## 12. PR sequence

| # | PR | Contents | Size |
| --- | --- | --- | --- |
| 1 | Email-code store and core | `EmailCode` entity, `EmailCodeConfiguration`, `UseEmailCodes()`, internal `EmailCodeStore<TContext>` (issue, supersede, CAS attempt and consume, cleanup), generator and hasher, `EmailCodeOptions` + validator, `TimeProvider`. Unit tests 1–4 and 6. No routes. | M (~500 LOC + tests) |
| 2 | Send and verify endpoints | `IEmailCodeSender<TUser>`, dev sender + Production validator, DTOs, `EmailCodeEndpoints<TUser>`, `MapEmailCodeEndpoints`, `AddEmailCodeEndpoints`, the `EmailCode.Send` rate-limit policy, `IEmailCodeSignInCompleter` + Identity/JWT completers + shared scheme helper, all of rules 1–13 and 15 including 2FA, lockout, stamp, and the unconfirmed policy, log events. Integration tests 1–5 and 7–13, 14–15, 18–20. | L (~900 LOC + tests) |
| 3 | Facade wiring | `AuthEndpointsOptions.EmailCode`, wiring in `AddAuthEndpointsCore` and `MapAuthEndpointsCore`, test host `AE_EMAIL_CODE`. Integration test 6. | S |
| 4 | `AllowSignUp` | Rule 14 with the duplicate race. Integration test 16. | S |
| 5 | Magic link | Link token issue and verify, `MagicLink` options, URL builder + origin validation. Unit test 5, integration test 17. | S–M |
| 6 | Docs, skill, release | Pages in §9, `v3.3.0.md`, skills, csproj `<Version>3.3.0</Version>`. | M (docs) |

PRs 4 and 5 can slip to 3.4.0 without blocking a 3.3.0 that ships code-only sign-in.

---

## 13. Open decisions for Made

1. **An unconfirmed account that already has a password, passkey, or external login** (the pre-hijack case). Options:
   - **(a) `ConfirmAndResetCredentials`** (my pick): the code confirms the email, the library removes those credentials, and the stamp rotates.
   - **(b) `Reject`:** the generic `401`, and the user has to go through password reset.
   - (c) Confirm and keep the credentials. This is unsafe and not offered.
2. **Magic link in 3.3.0, or code-only first.** My pick is to ship it in 3.3.0, off by default, as its own PR (PR 5). The alternative is to ship code-only and add the link in 3.4.0 after real use.
3. **Wrong email codes count toward Identity lockout** (`CountFailuresTowardLockout = true`, my pick). This is consistent with `lockoutOnFailure: true` everywhere else. The cost is that anyone who knows an email can lock that account, including its password login, though that's already true with wrong passwords. The alternative, `false`, relies only on per-code attempts and send limits.
