---
seo:
  title: AuthEndpoints — ASP.NET Core Identity auth library
  description: 'Ready-made sign-up and sign-in endpoints for ASP.NET Core Identity: passwords, passkeys, GitHub and Google, two-factor codes, cookies, and tokens.'
---

::u-page-hero{class="dark:bg-gradient-to-b from-zinc-900 to-zinc-950"}
---
orientation: horizontal
---
#top
:hero-background

#title
[AuthEndpoints]{.text-primary}

#description
Ready-made sign-up and sign-in endpoints for ASP.NET Core Identity: passwords, passkeys, GitHub and Google, two-factor codes, cookies, and tokens.

#links
  :::u-button
  ---
  to: /getting-started
  size: xl
  trailing-icon: i-lucide-arrow-right
  ---
  Get started
  :::

  :::u-button
  ---
  icon: i-simple-icons-github
  color: neutral
  variant: outline
  size: xl
  to: https://github.com/madeyoga/AuthEndpoints
  target: _blank
  ---
  GitHub
  :::

#default
  :::prose-pre
  ---
  code: |
    builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(o =>
    {
        o.Passkeys.ServerDomain = "example.com";
    });
    builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

    var app = builder.Build();
    app.UseAuthEndpoints();
    app.MapAuthEndpoints<AppUser>();
  filename: Program.cs
  ---

  ```cs [Program.cs]
  builder.Services.AddAuthEndpoints<AppUser, AppDbContext>(o =>
  {
      o.Passkeys.ServerDomain = "example.com";
  });
  builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

  var app = builder.Build();
  app.UseAuthEndpoints();
  app.MapAuthEndpoints<AppUser>();
  ```
  :::
::

::u-page-section{class="dark:bg-zinc-950"}
#title
What AuthEndpoints can do

#description
Each capability links to the guide that shows you how to use it.

#features
  :::u-page-feature
  ---
  icon: i-lucide-user-plus
  to: /guides/registration
  ---
  #title
  Register with an email and password

  #description
  Create accounts and send confirmation email.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-fingerprint
  to: /guides/registration#register-with-a-passkey
  ---
  #title
  Register with a passkey

  #description
  Create passwordless accounts with WebAuthn.
  :::

  :::u-page-feature
  ---
  icon: i-simple-icons-github
  to: /guides/sign-in#sign-in-with-github-or-google
  ---
  #title
  GitHub and Google sign-in

  #description
  Add social sign-in in a separate preview package.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-cookie
  to: /guides/sign-in#sign-in-with-a-password-and-a-cookie
  ---
  #title
  Cookie sessions

  #description
  Sign browser users in with a secure app cookie.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-smartphone
  to: /guides/sign-in#sign-in-with-a-password-and-identity-bearer-tokens
  ---
  #title
  Identity bearer tokens

  #description
  Issue access and refresh tokens for mobile apps.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-key-square
  to: /guides/sign-in#sign-in-with-a-password-and-a-jwt
  ---
  #title
  JWT with a refresh cookie

  #description
  Issue short-lived JWTs with rotating refresh tokens.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-key-round
  to: /guides/sign-in#sign-in-with-a-passkey
  ---
  #title
  Passkey sign-in

  #description
  Sign users in with a passkey.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-shield-check
  to: /guides/two-factor
  ---
  #title
  Two-factor authentication

  #description
  Turn on authenticator codes and recovery codes.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-rotate-ccw-key
  to: /guides/reset-password
  ---
  #title
  Password reset

  #description
  Send reset codes and set a new password.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-mail
  to: /guides/manage-account
  ---
  #title
  Email change

  #description
  Change the email after the user confirms it.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-list
  to: /guides/manage-passkeys
  ---
  #title
  Passkey management

  #description
  Add, rename, and remove passkeys.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-link
  to: /guides/link-external-accounts
  ---
  #title
  Account linking

  #description
  Link and unlink GitHub or Google accounts.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-shield-alert
  to: /guides/step-up
  ---
  #title
  Step-up (ReAuth)

  #description
  Ask for proof again before sensitive changes.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-lock
  to: /concepts/security-model
  ---
  #title
  Built-in protection

  #description
  CSRF, rate limits, lockout, and checks at startup.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-blocks
  to: /composables
  ---
  #title
  Composable modules

  #description
  Map only the routes you need, on your own prefixes.
  :::
::

::u-page-section{class="dark:bg-zinc-950"}
#title
Map auth in minutes

#description
Start with the facade, then compose modules when you need custom paths or a JWT-only stack.

#links
  :::u-button
  ---
  to: /getting-started/quick-start
  size: xl
  trailing-icon: i-lucide-arrow-right
  ---
  Quick start
  :::

  :::u-button
  ---
  to: /composables
  color: neutral
  variant: outline
  size: xl
  ---
  Composable endpoints
  :::

:stars-bg
::
