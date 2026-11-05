# List and revoke sessions

Active sessions are off by default and support cookie and JWT sessions. Identity bearer fails at startup when it is mapped with active sessions on. Call `modelBuilder.UseActiveSessions()` (after `UseRefreshToken()` for JWT) and migrate (`AuthEndpointsActiveSessions`, plus a nullable `SessionId` on refresh tokens for JWT). Call `AddActiveSessions<TUser, TContext>(Action<ActiveSessionOptions>?)` after `AddPasswordAuth` or `AddJwtEndpoints` and after any custom refresh-token service or access-token generator. Map `MapActiveSessionEndpoints<TUser>()` on the sign-in prefix.

| Option | Default | Meaning |
| --- | --- | --- |
| `LastSeenUpdateInterval` | 5 minutes | Minimum time between `lastSeenAt` writes. Must not be negative. |
| `RevalidationInterval` | 30 seconds | How long a cookie request trusts the last session check. `TimeSpan.Zero` checks every request. Must not be negative. |
| `CleanupInterval` | 1 hour | How often expired and revoked records are deleted. Must be positive. |

| Method | Path | Auth | CSRF | ReAuth | Result |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/auth/sessions` | Yes | | | `200` `[{ id, userAgent, createdAt, lastSeenAt, current }]` |
| `DELETE` | `/auth/sessions/{id}` | Yes | Yes | Yes | `204`, or `404` when the session is not the caller's |
| `POST` | `/auth/sessions/revokeOthers` | Yes | Yes | Yes | `200` `{ revoked }`, or `409` when the caller has no current session |

CSRF applies to cookie callers. A revoked cookie gets `401` on its next request. A revoked JWT session loses its refresh tokens. Issued access tokens stay valid until they expire.

Guide: [List and revoke signed-in sessions](https://authendpoints.harten.id/guides/active-sessions).
