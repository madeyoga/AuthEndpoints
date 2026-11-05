# Add GitHub or Google

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
| `GET` | `/providers` | | | | |
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

Unlink requires a signed-in user on a registered AuthEndpoints scheme (`Identity.Application`, `Identity.Bearer`, or JWT bearer), the antiforgery filter, and a ReAuth proof for that same user. A bearer `Authorization` header skips the antiforgery check under the bearer-header rule in [csrf.md](csrf.md). A missing login is `404`. Success is `204`. Removal is refused with problem title `last_signin_method` when it would delete the last sign-in method. Email code counts only when email-code sign-in is mapped and the email is confirmed.

`GET /providers` needs no sign-in. It returns `[{ "scheme", "displayName" }]` for each registered provider, in registration order. `displayName` falls back to the scheme. `MapExternalAccountEndpoints` works with zero providers: `/providers` and `/logins` return `[]`, and no link routes are mapped.

Module: [External OAuth](https://authendpoints.harten.id/modules/external-oauth).
