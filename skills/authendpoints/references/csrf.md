# Send the CSRF token

Cookie sessions and JWT cookie refresh need antiforgery on unsafe methods that change an existing session. Login, register, forgot-password, reset-password, and both email-code routes skip antiforgery.

1. `GET /auth/csrfToken` returns `{ "csrfToken" }` and sets the antiforgery cookie. JWT body refresh has no such route. The 3.x cookie facade uses `GET /identity/csrfToken`. The 3.x JWT prefix uses `GET {Jwt.Path}/csrfToken` (default `/auth/csrfToken`) when refresh transport is `Cookie`.
2. Send that value in the antiforgery header.
3. Send cookies (`credentials: "include"`, or Axios `withCredentials`).

The library calls `AddAntiforgery()` with no header override. The ASP.NET Core header name is `RequestVerificationToken`. A host may set `AntiforgeryOptions.HeaderName`. The client uses the header the host configured. A missing or invalid token is `400` with the body `Invalid or missing CSRF token.`

The filter skips validation only when the application cookie does not authenticate the request, the request has a non-empty `Authorization: Bearer` header, and a scheme in `AuthEndpointsAntiforgeryOptions.BearerSchemes` authenticates that header. The default list is `Identity.Bearer` and the JWT bearer scheme. A token read from a cookie in `OnMessageReceived` still needs the CSRF token when that header is absent. An application cookie still needs the CSRF token when a bearer token is also present.

Add a host or package token scheme with `services.Configure<AuthEndpointsAntiforgeryOptions>(o => o.BearerSchemes.Add("MyTokenScheme"))`. Add only schemes that read the `Authorization: Bearer` header. Cookie-handler schemes in the list are ignored. A scheme that reads another header (an API key in `X-Api-Key`) does not skip the check without `Authorization: Bearer`. `AuthEndpoints.OpenIddict` adds its validation scheme to the list. The same list decides whether `POST /confirmIdentity` sets the ReAuth cookie.

`RequireAntiforgery(allowBearer: false)` on a route or group requires the token from every caller, including a valid bearer, and ignores the list. Use it for routes a token must never call, such as consent approval or account deletion. `RequireAntiforgery()` keeps the bearer skip.

Anonymous passkey ceremonies (`POST /passkeys/requestOptions`, `POST /passkeys/register/options`, `POST /passkeys/register`, `POST /passkeys/login`) require the token for a cookie session and for JWT cookie refresh. Identity bearer and JWT body refresh omit the filter on those four routes. Pass `AuthEndpointsSession` to `MapPasskeySignInEndpoints` or `MapPasskeySignUpEndpoints` to select that rule. With no session argument, antiforgery follows `SignInCompletionOptions.Default` when `IdentityPasskeySignInCompleter<TUser>` is still the registered passkey completer. With no default, the token stays required. A custom `IPasskeySignInCompleter<TUser>` keeps the token on those parameterless maps. Signed-in passkey changes always attach the filter. The bearer-header skip above still applies.

`MapBearerAuthEndpoints` maps no `csrfToken` route.

Rules: [Antiforgery (CSRF) rules](https://authendpoints.harten.id/modules/csrf).
