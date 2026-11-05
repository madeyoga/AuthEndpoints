# Use a JWT session

Set `Session` to `AuthEndpointsSession.Jwt` and pass `Jwt`. Call `modelBuilder.UseRefreshToken()` and migrate. The table is `AuthEndpoints.AuthEndpointsRefreshTokens`. The absolute family lifetime adds non-null `AbsoluteExpiresAt`. Backfill existing rows from `ExpiresAt`. Recreate the table when upgrading from plaintext storage.

```cs
builder.Services.AddPasswordAuth<AppUser, AppDbContext>(o =>
{
	o.Session = AuthEndpointsSession.Jwt;
	o.Jwt = jwt =>
	{
		jwt.Issuer = "https://example.com";
		jwt.Audience = "https://example.com";
		jwt.SigningOptions.SymmetricKey = key;
	};
});
```

Password sign-in is `POST /auth/create`. The JSON body is `accessToken` and `tokenType` `Bearer`. A missing second factor is `401` with title `RequiresTwoFactor`, detail `Two-factor authentication is required.`, and extension `requiresTwoFactor` set to true. A wrong authenticator code and a wrong recovery code are `401` with detail `Invalid credentials.` Both count toward lockout. `POST /auth/logout` reads the refresh token. It has no access-token check. Refresh transport defaults to the HttpOnly cookie `AuthEndpoints.Jwt.RefreshToken` (`SameSite=Strict`, path `/`). `RefreshTokenTransport.Body` also returns `refreshToken` from create, email-code verify, passkey sign-in, and refresh. Body refresh and logout accept `{ "refreshToken" }`, skip antiforgery, and leave `GET /auth/csrfToken` unmapped. A non-JSON body on those two routes is `415`.

`AddJwtEndpoints` copies `SimpleJwtOptions.RefreshTokenTransport` onto `JwtSessionOptions` when the value is `Body`. An earlier `Configure<JwtSessionOptions>` stays when transport is left at `Cookie`. A configure registered after `AddJwtEndpoints` replaces the result.

Cookie-transport refresh returns `{ "accessToken" }` and requires the CSRF token. `GET /auth/verify` with `Authorization: Bearer` returns `204` and no refresh token.

Every refresh rotates. Reuse of an old token revokes the family. A second refresh that presents the same token after the first rotation revokes the family too. Logout and a security-stamp change revoke the family. `AbsoluteLifetime` and `RefreshTokenLifetime` both default to 14 days. Rotation leaves the absolute cap where it started.

In Production, set `Issuer` and `Audience` to values other than the defaults `Jwt` and `JwtAudience`. A symmetric key is at least 32 UTF-8 bytes. `Algorithm` `Rsa` reads `SigningOptions.RsaKey`. `Ecdsa` reads `EcdsaKey`. `X509` reads `Certificate`.

Module: [JWT](https://authendpoints.harten.id/modules/jwt).
