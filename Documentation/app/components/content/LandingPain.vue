<script setup lang="ts">
const calls = [
  'AddAuthentication()',
  'AddCookie()',
  'AddJwtBearer()',
  'AddAuthorization()',
  'UseAuthentication()',
  'UseAuthorization()'
]

const ghosts = [
  { text: 'AddAuthentication()', class: 'left-[4%] top-[9%] -rotate-6 text-sm' },
  { text: 'AddCookie()', class: 'left-[4%] top-[20%] rotate-2 text-sm hidden lg:block' },
  { text: 'AddJwtBearer()', class: 'right-[3%] top-[20%] rotate-3 text-sm hidden lg:block' },
  { text: 'AddAuthorization()', class: 'left-[4%] bottom-[9%] -rotate-2 text-sm' },
  { text: 'UseAuthentication()', class: 'right-[3%] top-[9%] -rotate-3 text-sm' },
  { text: 'UseAuthorization()', class: 'right-[4%] bottom-[9%] rotate-2 text-sm' }
]

const asides = [
  { text: 'JWT in localStorage?', class: 'left-[8%] bottom-[22%] -rotate-2 hidden xl:block' },
  { text: 'Or in a cookie?', class: 'right-[8%] bottom-[22%] rotate-1 hidden xl:block' }
]
</script>

<template>
  <UPageSection
    id="confused-by-auth"
    class="scroll-mt-24 overflow-hidden dark:bg-zinc-950"
    :ui="{
      container: 'relative z-10 py-16 sm:py-20 lg:flex lg:py-28',
      leading: 'mb-4 justify-center sm:hidden',
      title: 'text-balance',
      description: 'mx-auto max-w-3xl text-pretty'
    }"
  >
    <template #top>
      <div
        class="pointer-events-none absolute inset-0"
        style="background: radial-gradient(ellipse 78% 58% at 50% 42%, color-mix(in oklab, var(--ui-primary) 18%, transparent), transparent 72%);"
        aria-hidden="true"
      />
      <div
        class="pointer-events-none absolute inset-0 hidden overflow-hidden sm:block"
        style="mask-image: radial-gradient(ellipse 72% 68% at 50% 50%, transparent 0%, transparent 58%, #000 100%);"
        aria-hidden="true"
      >
        <p
          v-for="ghost in ghosts"
          :key="ghost.text"
          class="absolute font-mono whitespace-nowrap text-muted/80 select-none dark:text-zinc-400/60"
          :class="ghost.class"
        >
          {{ ghost.text }}
        </p>
        <p
          v-for="aside in asides"
          :key="aside.text"
          class="absolute font-sans text-sm italic whitespace-nowrap text-muted/90 select-none dark:text-muted/70"
          :class="aside.class"
        >
          {{ aside.text }}
        </p>
      </div>
    </template>

    <template #leading>
      <div
        class="flex max-w-lg flex-wrap justify-center gap-x-3 gap-y-1 text-center font-mono text-xs text-dimmed"
        aria-hidden="true"
      >
        <span
          v-for="call in calls"
          :key="call"
        >
          {{ call }}
        </span>
        <span class="font-sans italic">JWT in localStorage?</span>
        <span class="font-sans italic">Or in a cookie?</span>
      </div>
    </template>

    <template #title>
      Confused by <span class="text-primary">ASP.NET&nbsp;Core&nbsp;auth?</span>
    </template>

    <template #description>
      Writing code is cheap now. Bugs aren't. Shared code is still the fastest way to get fewer of them, and AuthEndpoints is that shared code for auth.
    </template>
  </UPageSection>
</template>
