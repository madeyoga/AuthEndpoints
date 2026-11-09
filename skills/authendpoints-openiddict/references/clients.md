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

## Redirect URIs

An authorize request's `redirect_uri` must match one of the client's registered redirect URIs exactly, with one exception from RFC 8252 §7.3: on a loopback IP literal, `http://127.0.0.1` or `http://[::1]`, the port may differ. A native app or CLI can register `http://127.0.0.1/callback` and listen on whatever port is free. The scheme, host, path, and query must still match, so `http://127.0.0.1:51234/callback` matches a registered `http://127.0.0.1:9/callback`, but `/other`, `127.0.0.2`, or `[::1]` do not. This applies to every client: from configuration, dynamic registration, or developer apps.

`localhost` is matched exactly, port included. RFC 8252 §8.3 recommends the IP literals over `localhost`, so register `http://127.0.0.1/…` for a native app. The token request must repeat the `redirect_uri` sent at authorize, port included.
