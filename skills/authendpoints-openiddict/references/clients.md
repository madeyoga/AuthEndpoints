# Clients

## Clients from configuration

```json
{
  "OAuthServer": {
    "Clients": [
      {
        "ClientId": "my-cli",
        "DisplayName": "My CLI",
        "RedirectUris": [ "http://127.0.0.1:8765/callback" ],
        "Scopes": [ "api" ]
      }
    ]
  }
}
```

`SeedOAuthClientsAsync` creates each client or updates it in place. A client with no `ClientSecret` is public. A client with a secret is confidential; keep the secret in a secret store, not in `appsettings.json`. Empty `Scopes` or `Resources` means every configured one. Every client must use PKCE.

## Dynamic registration (optional)

```csharp
options.DynamicRegistration.Enabled = true;
options.DynamicRegistration.PermitsPerMinute = 10; // per client IP
options.DynamicRegistration.AllowedScopes.Add("mcp"); // optional: scopes anyone may register for
```

`POST /connect/register` accepts only public clients (`token_endpoint_auth_method` `none`, no `client_secret`), the `authorization_code` and `refresh_token` grants, the `code` response type, and configured scopes. Each redirect URI must be `https`, or `http` on `localhost`, `127.0.0.1`, or `[::1]`, with no fragment and no user info. The rate limit runs inside the endpoint, so it works without `UseRateLimiter`. Behind a proxy, configure forwarded headers so the client IP is right.

By default a registered client may hold every configured scope. Anyone can register, so if a scope is meant only for your own clients (for example one that acts as the user's whole account), list the scopes registered clients may use in `AllowedScopes`. Each must be in `Scopes`; `offline_access` is always allowed, and `openid` must be listed for registered clients to use OpenID Connect. A registration asking for another scope is rejected with `invalid_client_metadata`, and `/connect/authorize` holds clients registered before the list was set to it too. Configured clients and developer apps are not affected.

A registered client that no user approved within `UnusedClientLifetime` (24 hours) is deleted by the background cleanup. Seeded clients are never deleted.

## Client ID metadata documents (optional)

The MCP authorization spec prefers this over dynamic registration. A client uses an `https` URL as its `client_id`, and serves a JSON document there that describes it ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)):

```json
{
  "client_id": "https://assistant.example.com/oauth/client.json",
  "client_name": "Example Assistant",
  "redirect_uris": [ "https://assistant.example.com/oauth/callback" ],
  "grant_types": [ "authorization_code", "refresh_token" ],
  "token_endpoint_auth_method": "none"
}
```

```csharp
options.ClientMetadataDocuments.Enabled = true;
options.DynamicRegistration.AllowedScopes.Add("mcp"); // also limits these clients
```

With it on, the authorization server metadata has `client_id_metadata_document_supported: true`, and `/connect/authorize` resolves a `client_id` that is an `https` URL before OpenIddict looks the client up:

- **The URL** must be `https`, with a path other than `/`, and no query, fragment, user info, or `.`/`..` segments. It is compared as a string and never normalized. It may be up to 255 characters.
- **The fetch** goes only to public addresses. The host name is resolved first and every address must be public: loopback, private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`), link-local (`169.254/16`, `fe80::/10`, which covers cloud metadata endpoints), shared, documentation, and multicast addresses are refused, and the connection goes only to the addresses that were checked, so a second DNS answer cannot redirect it. Redirects are not followed; no cookies, credentials, or proxy are used; it times out after `FetchTimeout` (5 seconds) and reads at most `MaxDocumentBytes` (5 KB). `Accept: application/json` is sent and only `200` is accepted. Fetches are not logged.
- **The document** must have `client_id` equal to the URL, and `redirect_uris` under the same rules as dynamic registration (`https`, or `http` on a loopback host, where `127.0.0.1` and `[::1]` may use any port). Only public clients are accepted: no `client_secret`, no shared-secret method, and `none` must be the client's `token_endpoint_auth_method` or one of its `token_endpoint_auth_methods_supported` (a document with neither means `none`). `grant_types`, when present, must include `authorization_code` (a refresh token is issued only if it also lists `refresh_token`), and `response_types` must include `code`. `client_name` is optional; without it, the card shows the host.
- **Scopes** follow `DynamicRegistration.AllowedScopes`, as for registered clients. The document's own `scope` is ignored, because one document serves every server. Metadata document clients and registered clients are both self-asserted and unauthenticated, so they share `AllowedScopes`, `UnusedClientLifetime`, `MaxRedirectUris`, and `MaxClientNameLength`. Separate settings can be added later, falling back to these.
- **Storage.** The client is stored in OpenIddict's application store, as a public client, so authorizations, refresh, revocation, and `RevokeAuthorizationAsync` work as for any client. It carries the same creation marker as a registered client, so the cleanup deletes one that no user approved within `DynamicRegistration.UnusedClientLifetime`; it is simply fetched again next time. A configured client, developer app, or registered client is never replaced by a fetched document, even if its id is a URL.
- **Caching.** The stored copy is reused until its `Cache-Control: max-age` runs out, kept between `MinCacheDuration` (5 minutes, also used for `no-cache`, `no-store`, or no header) and `MaxCacheDuration` (24 hours). Then the next authorize request fetches it again and updates the stored client in place. If that fetch fails on the network (timeout, connection error, `5xx`, `429`), the stored copy is used and fetched again on the next request. If the new document's `client_id` no longer matches its URL, the request is refused and every authorization and token the client holds is revoked, as the draft recommends. Any other invalid document refuses new authorizations only: grants the client already holds keep working. Errors are never cached.
- **Errors.** A refused client gets `invalid_client` on this server's error page. The browser is never sent to the client's redirect URI.
- **Limits.** Fetches are limited per caller IP address with `ClientMetadataDocuments.FetchesPerMinute` (20 by default), because an anonymous authorize request can cause one; a stored copy is reused without counting. Behind a proxy, configure forwarded headers so the caller IP is right.
- **Hosts.** `DeniedHosts` and `AllowedHosts` take host names, or `*.example.com` for subdomains. Empty `AllowedHosts` accepts any public host. For a decision the lists cannot express, register a filter; it runs before every fetch and before a stored client is reused:

```csharp
builder.Services.AddOAuthServer<AppUser, AppDbContext>(options => { … })
    .AddClientMetadataHostFilter<TrustedClientHosts>();

public sealed class TrustedClientHosts(AppDbContext db) : IOAuthClientMetadataHostFilter
{
    public async ValueTask<bool> IsAllowedAsync(Uri clientId, CancellationToken ct)
        => await db.TrustedClientHosts.AnyAsync(host => host.Name == clientId.IdnHost, ct);
}
```

The consent card gets `clientHost`, the host of the `client_id` URL (with the port when it is not the default), so your page can show which domain published the client next to its name. Turning the option off stops clients created from metadata documents everywhere: `/connect/authorize` refuses them, and so does `/connect/token`, for both code exchange and refresh (`invalid_client`). Access tokens they already hold work until they expire (`AccessTokenLifetime`, 15 minutes by default).

`private_key_jwt` client authentication (with `jwks` or `jwks_uri`) is not supported yet. A document that offers it next to `none` is accepted as a public client; one that offers only `private_key_jwt` is refused with `invalid_client` and the description "private_key_jwt is not supported for client ID metadata documents yet".

The `client_id` columns of `OpenIddictApplications` and `OAuthRequests` are 255 characters wide, so a metadata URL fits. Add a migration after upgrading (`dotnet ef migrations add WidenOAuthClientId`, then apply it as you apply your other migrations).

## Redirect URIs

An authorize request's `redirect_uri` must match one of the client's registered redirect URIs exactly, with one exception from RFC 8252 §7.3: on a loopback IP literal, `http://127.0.0.1` or `http://[::1]`, the port may differ. A native app or CLI can register `http://127.0.0.1/callback` and listen on whatever port is free. The scheme, host, path, and query must still match, so `http://127.0.0.1:51234/callback` matches a registered `http://127.0.0.1:9/callback`, but `/other`, `127.0.0.2`, or `[::1]` do not. This applies to every client: from configuration, dynamic registration, or developer apps.

`localhost` is matched exactly, port included. RFC 8252 §8.3 recommends the IP literals over `localhost`, so register `http://127.0.0.1/…` for a native app. The token request must repeat the `redirect_uri` sent at authorize, port included.
