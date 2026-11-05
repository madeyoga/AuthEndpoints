# Developer apps

Signed-in users register OAuth apps they own and get a client id (and, for a confidential app, a client secret), the way the GitHub and Google developer consoles work. `MapOAuthServer()` maps a JSON API for your developer console page (or `MapOAuthDeveloperAppEndpoints()` without the recipe; `parts.DeveloperApps = false` turns it off). Every route requires the signed-in user (`AuthenticationScheme`), and the writes require a CSRF token for cookie callers, as the consent API does.

| Route | |
| --- | --- |
| `GET /oauth/apps` | The caller's apps. |
| `POST /oauth/apps` | Register an app. `201` with `{ app, clientSecret }`. |
| `GET /oauth/apps/{id}` | One app. |
| `PUT /oauth/apps/{id}` | Edit the name, homepage, description, and redirect URIs. |
| `DELETE /oauth/apps/{id}` | Delete the app and every authorization and token issued to it. |
| `POST /oauth/apps/{id}/secret` | Confidential apps only: replace the secret. `{ app, clientSecret }`. The old secret stops working at once. |

```json
{
  "name": "My dashboard",
  "homepageUrl": "https://dashboard.example.com",
  "description": "Optional",
  "redirectUris": [ "https://dashboard.example.com/oauth/callback" ],
  "confidential": true
}
```

There is no SPA, native, or web type to pick. The only choice is whether the app can keep a secret:

- **Confidential** (`"confidential": true`, for server-side apps): a client secret is generated and returned once, with `Cache-Control: no-store`. Only its hash is stored. The app authenticates at the token endpoint with `client_secret_basic` or `client_secret_post`, and still uses PKCE.
- **Public** (the default, for SPAs, desktop and mobile apps, and CLIs): no secret, PKCE only.

`confidential` is fixed at creation and ignored on edit. Each redirect URI is checked on its own:

| Redirect URI | Public | Confidential |
| --- | --- | --- |
| `https://…` | yes | yes |
| `http://localhost`, `http://127.0.0.1`, `http://[::1]` | yes | yes |
| A reverse-domain private-use scheme (RFC 8252 §7.1), for example `com.example.app:/callback` | yes | no |
| `http://` on any other host, single-word schemes (`myapp:`, `javascript:`, `data:`, `file:`), a fragment, or user info | no | no |

Loopback IP redirects may use any port. See [Redirect URIs](clients.md#redirect-uris).

Settings, under `options.DeveloperApps`:

| Option | Default | |
| --- | --- | --- |
| `RequireApproval` | `false` | New apps start as `PendingApproval` and cannot sign anyone in until an admin approves them. |
| `MaxAppsPerUser` | 10 | A user at the limit gets `409`. |
| `MaxRedirectUris` | 10 | |

Admin review is in `IOAuthDeveloperAppService`, not in the mapped API, because only your app knows who an admin is. `ListByStatusAsync(OAuthDeveloperAppStatus.PendingApproval)` returns the review queue, and `SetStatusAsync` approves (`Active`) or turns an app off (`Disabled`). Setting any status other than `Active` through `SetStatusAsync` revokes the app's authorizations and tokens. The authorize endpoint answers `unauthorized_client` for an app that is not active, and so does the token endpoint for a code or refresh token issued before the change. Protect your admin endpoints yourself.

With `RequireApproval`, an edit that changes an active app's name or redirect URIs sends it back to `PendingApproval`, so an owner cannot swap in a new redirect or a misleading name after approval. Until an admin approves it again, new sign-ins and token refreshes get `unauthorized_client`. Existing grants are not revoked, so they work again once the app is approved. Access tokens that were already issued keep working until they expire. Homepage and description edits do not need review, and editing a disabled app leaves it disabled.

The owner methods of the same service (`ListAsync`, `CreateAsync`, `UpdateAsync`, …) take the caller's user id, for hosts that want their own routes.

When an owner's account is deleted, the cascade removes the app's row. From then on, the authorize and token endpoints refuse its client, and the next cleanup pass deletes it. Developer apps are never treated as unused dynamic registrations.

Developer apps and [dynamic registration](clients.md#dynamic-registration-optional) are separate. Anonymous registration stays the path for native apps and CLIs that register themselves. Developer apps are for people building an integration with your service. On the user side, `IOAuthConsentService.RevokeAuthorizationAsync` still disconnects one app from one account.
