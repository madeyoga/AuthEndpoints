# Compose more than one session

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
