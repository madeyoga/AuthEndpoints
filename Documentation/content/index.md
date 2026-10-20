---
seo:
  title: AuthEndpoints — ASP.NET Core Identity auth library
  description: 'Sign-up and sign-in endpoints for ASP.NET Core Identity: passwords, passkeys, emailed codes, GitHub and Google, two-factor codes, cookies, and tokens.'
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
Ready-made sign-up and sign-in endpoints for ASP.NET Core Identity: passwords, passkeys, emailed codes, GitHub and Google, two-factor codes, cookies, and tokens.

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
    builder.Services.AddPasswordAuth<AppUser, AppDbContext>();
    builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

    var app = builder.Build();
    app.UseAuthEndpoints();
    app.MapPasswordAuth<AppUser>();
  filename: Program.cs
  ---

  ```cs [Program.cs]
  builder.Services.AddPasswordAuth<AppUser, AppDbContext>();
  builder.Services.AddTransient<IEmailSender<AppUser>, MyEmailSender>();

  var app = builder.Build();
  app.UseAuthEndpoints();
  app.MapPasswordAuth<AppUser>();
  ```
  :::
::

::landing-pain
::

::landing-setup
::

::u-page-section{id="what-authendpoints-can-do" class="dark:bg-zinc-950"}
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
  Add GitHub or Google sign-in. The endpoints are in the core package.
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
  icon: i-lucide-mail
  to: /guides/email-code
  ---
  #title
  Emailed one-time code

  #description
  Sign in with a code. Sign-up and magic links stay off until you enable them.
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

  :::u-page-feature
  ---
  icon: i-lucide-arrow-left-right
  to: /concepts/compare#what-mapidentityapi-maps
  ---
  #title
  MapIdentityApi alternative

  #description
  Logout, chosen routes, JWT, and passkeys.
  :::
::

::u-page-section{class="dark:bg-zinc-950"}
#title
I want to

#description
Each line is one task.

- [Register users](/guides/registration)
- [Sign users in](/guides/sign-in)
- [Turn on two-factor authentication](/guides/two-factor)
- [Reset a forgotten password](/guides/reset-password)
- [Add, rename, and remove passkeys](/guides/manage-passkeys)
- [Sign in with an emailed code](/guides/email-code)
- [Add GitHub or Google](/guides/registration#register-with-github-or-google)
- [Require step-up before sensitive actions](/guides/step-up)
- [Run an app with no public sign-up](/guides/internal-app)
- [Upgrade to 4.0](/getting-started/upgrading-to-4)

The same list, plus sign-out, email change, and production, is on [Guides](/guides#i-want-to).
::

::u-page-section{class="dark:bg-zinc-950"}
#title
Start with password sign-in

#description
The quick start uses AddPasswordAuth and MapPasswordAuth. Pick another setup when you need JWT, passkeys, an emailed code, or an external provider.

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
  to: /getting-started/choose-a-sign-in-stack
  color: neutral
  variant: outline
  size: xl
  ---
  Choose your sign-in setup
  :::

:stars-bg
::
