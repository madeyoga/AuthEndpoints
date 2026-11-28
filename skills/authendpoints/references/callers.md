# People and agents

`User.GetCallerKind()` returns a `CallerKinds` value: `person` (application cookie, Identity bearer, AuthEndpoints JWT), `delegated` (an OAuth access token from `AuthEndpoints.OpenIddict`), or `api_key`. The kind is the `ae:caller` claim (`CallerKinds.ClaimType`); the built-in sign-in identities are recognized by authentication type without it, and the claim is not written into cookies or tokens. A host scheme sets `ae:caller` itself; an identity without it from an unknown scheme has no kind (`null`). When a principal holds identities from several schemes, any kind other than `person` wins.

Delegated tokens also carry the RFC 8693 `act` claim, `{"client_id":"…"}`. Read it with `User.GetActingClientId()`.

## Keep a route for people

```csharp
app.MapPost("/billing/close-account", CloseAccount)
    .RequireAuthorization("app")
    .RequireDirectPerson();   // 403 for delegated tokens, API keys, and unknown kinds
```

`AuthorizationPolicyBuilder.RequireDirectPerson()` does the same in a named policy. It names no scheme; pair it with the route's own.

`RequireAuthEndpointsUser()` requires a direct person. Built-in routes that use it: `GET` and `POST /manage/info`, `POST` and `DELETE /manage/password`, `/resendConfirmationEmail`, `GET` and `POST /manage/2fa`, passkey management (`/passkeys/creationOptions`, `GET`/`POST`/`PATCH /passkeys`, `DELETE /passkeys/{id}`), ReAuth (`/confirmIdentity`, `/confirmIdentity/passkeyOptions`, `/confirmIdentity/emailCode/send`, `/manage/authMethods`), external sign-in (`/logins`, `/link/{scheme}`, its callback), and sessions (`/sessions`, `DELETE /sessions/{id}`, `/sessions/revokeOthers`). Put `RequireDirectPerson()` on the host's own account deletion and API key management routes.

## One handler per credential

```csharp
builder.Services.AddAuthentication().AddAnyCallerScheme(options =>
{
    options.BearerScheme = OAuthServerConstants.AccessTokenScheme; // default: JWT if registered, else Identity bearer
    options.ApiKeyScheme = "ApiKey";
    options.ApiKeyPrefix = "ak_";
});
```

Scheme name: `AuthEndpointsConstants.AnyCallerScheme` (`AuthEndpoints.AnyCaller`). `AnyCallerAuthenticationBuilderExtensions.SchemeName` has the same value and is obsolete. `OAuthServerConstants.AccessTokenScheme` is the OpenIddict validation scheme. `OAuthServerServiceCollectionExtensions.ValidationScheme` has the same value and is obsolete. An `Authorization` credential starting with `ApiKeyPrefix` goes to `ApiKeyScheme`, any other `Authorization` header to `BearerScheme`, and no header to `CookieScheme`. An invalid token with a valid cookie is `401`. The scheme is opt-in and does not change the default scheme. Set `ApiKeyScheme` and `ApiKeyPrefix` together or not at all.
