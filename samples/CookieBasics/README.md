# Cookie basics

Runnable cookie-facade sample: register (with email confirm), login, password reset, and authenticator 2FA.

This in-repo copy uses a **project reference** to `src/AuthEndpoints` so it tracks the library APIs. If you cloned a release tag without that project, add the published package instead:

```bash
dotnet add package AuthEndpoints --version 3.0.7
```

and remove the `ProjectReference`.

## Run

From the repository root (requires .NET 10):

```bash
dotnet run --project samples/CookieBasics
```

Listens on `http://localhost:5288`. Identity routes use the facade default **`/identity`**, so the [docs Examples](https://madeyoga.github.io/AuthEndpoints/examples) stay copy-pasteable.

SQLite file `cookie-basics.db` is created on start.

Confirmation links and password reset codes are printed to the **console** (`ConsoleEmailSender`). They are not sent over SMTP. Decode is already applied so you can paste the confirm URL and `resetCode` as printed.

Drive the four flows with [`CookieBasics.http`](CookieBasics.http) (Visual Studio / VS Code REST Client). Paste `userId` / `code` from the console after register, the reset code after forgot-password, and a TOTP from an authenticator after the 2FA `sharedKey` response.

In Development, Scalar is at `/scalar`.
