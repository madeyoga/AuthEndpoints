<script setup lang="ts">
type TokenKind = 'text' | 'string' | 'comment'

interface Token {
  text: string
  kind: TokenKind
}

interface SnippetLine {
  text: string
  hot: boolean
}

// Cookie is PasswordAuthOptions.Session's default. MapPasswordAuth mounts these
// under Path "/auth": register and confirmEmail, POST /login, forgot/reset,
// logout, and POST /manage/2fa. AuthEndpointsSession.Jwt maps POST /create
// instead of POST /login. The snippet sets Passkeys.ServerDomain, so passkey
// routes are part of "+ more".
const routes: { method: 'GET' | 'POST', path: string }[] = [
  { method: 'POST', path: '/auth/register' },
  { method: 'POST', path: '/auth/login' },
  { method: 'POST', path: '/auth/logout' },
  { method: 'GET', path: '/auth/confirmEmail' },
  { method: 'POST', path: '/auth/forgotPassword' },
  { method: 'POST', path: '/auth/resetPassword' },
  { method: 'POST', path: '/auth/manage/2fa' }
]

const lines: SnippetLine[] = [
  { text: 'builder.Services.AddDbContext<AppDbContext>(/* your provider */);', hot: false },
  { text: '', hot: false },
  { text: 'builder.Services.AddPasswordAuth<AppUser, AppDbContext>(o =>', hot: true },
  { text: '{', hot: true },
  { text: '    o.Passkeys.ServerDomain = "example.com";', hot: true },
  { text: '});', hot: true },
  { text: '', hot: false },
  { text: 'var app = builder.Build();', hot: false },
  { text: '', hot: false },
  { text: 'app.UseAuthEndpoints();', hot: true },
  { text: 'app.MapPasswordAuth<AppUser>();', hot: true }
]

function tokenize(source: string): Token[] {
  if (!source) {
    return [{ text: ' ', kind: 'text' }]
  }

  const tokens: Token[] = []
  const pattern = /("(?:[^"\\]|\\.)*"|\/\*[\s\S]*?\*\/)/g
  let last = 0

  for (const match of source.matchAll(pattern)) {
    const index = match.index ?? 0
    if (index > last) {
      tokens.push({ text: source.slice(last, index), kind: 'text' })
    }

    const value = match[0]
    tokens.push({
      text: value,
      kind: value.startsWith('/*') ? 'comment' : 'string'
    })
    last = index + value.length
  }

  if (last < source.length) {
    tokens.push({ text: source.slice(last), kind: 'text' })
  }

  return tokens
}

function tokenClass(kind: TokenKind, hot: boolean): string | undefined {
  if (!hot) {
    return kind === 'comment' ? 'italic' : undefined
  }

  if (kind === 'string') {
    return 'text-primary'
  }

  return undefined
}
</script>

<template>
  <UPageSection
    id="mapped-for-you"
    class="scroll-mt-24 overflow-x-hidden dark:bg-zinc-950"
    :ui="{ container: 'py-16 sm:py-20 lg:py-24' }"
  >
    <div class="mx-auto w-full max-w-6xl">
      <p class="mb-5 inline-flex max-w-full items-center gap-2 overflow-x-auto rounded-md bg-elevated/60 px-3 py-1.5 font-mono text-sm text-highlighted ring ring-default">
        <span
          class="text-primary select-none"
          aria-hidden="true"
        >$</span>
        <span class="whitespace-pre">dotnet add package AuthEndpoints</span>
      </p>

      <div class="grid grid-cols-1 items-stretch gap-6 lg:grid-cols-[minmax(0,1.45fr)_minmax(16rem,1fr)]">
        <div class="min-w-0">
          <p class="mb-2 text-sm font-semibold text-primary">
            Program.cs
          </p>
          <UPageCard
            variant="subtle"
            class="w-full min-w-0"
            :ui="{
              root: 'w-full min-w-0 overflow-hidden',
              container: 'w-full min-w-0 gap-y-0 p-0 sm:p-0'
            }"
          >
            <div class="max-w-full min-w-0 overflow-x-scroll sm:overflow-x-auto">
              <ol class="w-max min-w-full py-2 font-mono text-[13px] leading-6 sm:text-sm">
                <li
                  v-for="(line, index) in lines"
                  :key="index"
                  class="flex"
                  :class="line.hot ? 'bg-primary/15 text-highlighted dark:bg-primary/20' : 'text-dimmed'"
                >
                  <span
                    class="w-11 shrink-0 py-0.5 text-right text-dimmed/80 select-none"
                    aria-hidden="true"
                  >{{ index + 1 }}</span>
                  <code class="py-0.5 ps-3 pe-4 whitespace-pre">
                    <span
                      v-for="(token, tokenIndex) in tokenize(line.text)"
                      :key="tokenIndex"
                      :class="tokenClass(token.kind, line.hot)"
                    >{{ token.text }}</span>
                  </code>
                </li>
              </ol>
            </div>
          </UPageCard>
        </div>

        <div class="flex h-full min-w-0 flex-col">
          <p
            class="mb-2 hidden text-sm select-none lg:block"
            aria-hidden="true"
          >
            &nbsp;
          </p>
          <UPageCard
            variant="subtle"
            class="min-h-0 w-full flex-1 border-l-4 border-primary"
            :ui="{
              root: 'h-full',
              container: 'h-full',
              wrapper: 'h-full',
              body: 'flex-1',
              footer: 'mt-auto'
            }"
          >
            <template #body>
              <h2 class="text-lg font-semibold text-highlighted sm:text-xl">
                Mapped for you
              </h2>
              <ul class="mt-4 space-y-2.5 font-mono text-sm">
                <li
                  v-for="route in routes"
                  :key="route.method + route.path"
                  class="grid grid-cols-[3.25rem_minmax(0,1fr)] gap-x-3"
                >
                  <span class="font-semibold tracking-wide text-primary">{{ route.method }}</span>
                  <span class="text-highlighted">{{ route.path }}</span>
                </li>
                <li>
                  <NuxtLink
                    to="/modules/composition"
                    class="text-muted transition-colors hover:text-primary"
                  >
                    + more
                    <span class="sr-only">password auth routes</span>
                  </NuxtLink>
                </li>
              </ul>
            </template>
            <template #footer>
              <p class="rounded-full px-4 py-2 text-center text-sm text-balance text-muted ring ring-default">
                Cookie session by default · JWT via AuthEndpointsSession.Jwt
              </p>
            </template>
          </UPageCard>
        </div>
      </div>
    </div>
  </UPageSection>
</template>
