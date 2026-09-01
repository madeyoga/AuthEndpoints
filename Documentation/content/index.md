---
seo:
  title: AuthEndpoints — ASP.NET Core Identity auth library
  description: Ready-made auth endpoints on top of ASP.NET Core Identity, not a replacement. Cookies, JWT, and passkeys for first-party web and mobile apps.
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
Ready-made auth endpoints on top of ASP.NET Core Identity, not a replacement. Cookies, JWT, and passkeys for first-party web and mobile apps.

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
Built for first-party API auth

#description
Ship registration, sign-in, and account management without wiring every Identity endpoint yourself.

#features
  :::u-page-feature
  ---
  icon: i-lucide-zap
  ---
  #title
  Opinionated quick start

  #description
  `AddAuthEndpoints` / `UseAuthEndpoints` / `MapAuthEndpoints` give you cookie Identity and passkeys with secure defaults. Native and mobile hosts use `AddAuthEndpointsBearer` / `MapAuthEndpointsBearer` for Identity bearer tokens.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-blocks
  ---
  #title
  Composable modules

  #description
  Mix management, cookie, bearer, JWT, and passkeys on the route prefixes your host needs.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-key-round
  ---
  #title
  Cookie, JWT, and passkeys

  #description
  Choose cookie sessions, Identity bearer tokens, JWT with refresh cookies, and WebAuthn passwordless.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-shield-check
  ---
  #title
  Hardened defaults

  #description
  Rate limiting, antiforgery for cookie flows, lockout-aware login, and hashed JWT refresh tokens with reuse detection.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-shield-alert
  ---
  #title
  ReAuth step-up

  #description
  Confirm identity before sensitive manage and passkey mutations — cookie or header token for APIs.
  :::

  :::u-page-feature
  ---
  icon: i-lucide-factory
  ---
  #title
  Production validators

  #description
  Production rejects no-op email senders, missing passkey domains, and default JWT issuer/audience values.
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
