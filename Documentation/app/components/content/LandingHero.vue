<script setup lang="ts">
defineProps<{
  src: string
  poster: string
}>()

const reduceMotion = ref(false)
const playing = ref(false)
const video = ref<HTMLVideoElement | null>(null)

let motionQuery: MediaQueryList | undefined

async function syncMotion() {
  const reduce = motionQuery?.matches === true
  reduceMotion.value = reduce
  await nextTick()
  const player = video.value
  if (!player) {
    return
  }

  if (reduce) {
    if (playing.value) {
      return
    }
    player.pause()
    player.load()
    return
  }

  playing.value = false
  player.muted = true
  void player.play()
}

function onMotionChange() {
  void syncMotion()
}

onMounted(() => {
  motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  motionQuery.addEventListener('change', onMotionChange)
  void syncMotion()
})

onBeforeUnmount(() => {
  motionQuery?.removeEventListener('change', onMotionChange)
})

async function play() {
  const player = video.value
  if (!player) {
    return
  }

  player.muted = true
  try {
    await player.play()
    playing.value = true
    await nextTick()
    player.focus()
  } catch {
    playing.value = false
  }
}
</script>

<template>
  <UPageHero
    class="dark:bg-gradient-to-b from-zinc-900 to-zinc-950"
    orientation="vertical"
    :ui="{
      container: 'py-16 sm:py-20 lg:flex lg:py-24',
      headline: 'flex',
      title: 'mx-auto max-w-4xl text-balance text-4xl sm:text-5xl lg:text-6xl',
      description: 'mx-auto max-w-3xl'
    }"
  >
    <template #top>
      <HeroBackground />
    </template>

    <template #headline>
      <UBadge
        as="a"
        href="https://github.com/madeyoga/AuthEndpoints"
        target="_blank"
        rel="noopener noreferrer"
        color="neutral"
        variant="subtle"
        size="md"
        class="rounded-full hover:bg-accented focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-primary"
      >
        Open source · MIT · .NET 10
      </UBadge>
    </template>

    <template #title>
      <span class="text-primary">AuthEndpoints</span><span>: authentication library for ASP.NET Core Identity</span>
    </template>

    <template #description>
      Ready-made sign-up and sign-in endpoints for ASP.NET Core Identity: passwords, passkeys, email codes, OAuth, and 2FA.
    </template>

    <template #footer>
      <div class="flex flex-wrap justify-center gap-x-6 gap-y-3">
        <UButton
          to="/getting-started"
          size="xl"
          trailing-icon="i-lucide-arrow-right"
        >
          Get started
        </UButton>
        <UButton
          icon="i-simple-icons-github"
          color="neutral"
          variant="outline"
          size="xl"
          to="https://github.com/madeyoga/AuthEndpoints"
          target="_blank"
        >
          GitHub
        </UButton>
      </div>

      <p class="mx-auto mt-4 max-w-xl text-sm text-balance text-muted">
        Free and MIT licensed · No account or hosted service · Runs on your own database
      </p>

      <div class="relative mx-auto mt-8 aspect-video w-full max-w-5xl overflow-hidden rounded-lg bg-elevated ring ring-default sm:mt-10">
        <video
          ref="video"
          class="size-full object-contain"
          :src="src"
          :poster="poster"
          width="1920"
          height="1080"
          :autoplay="!reduceMotion"
          muted
          loop
          playsinline
          preload="metadata"
          :controls="reduceMotion && playing"
          aria-label="AuthEndpoints intro"
        />

        <button
          v-if="reduceMotion && !playing"
          type="button"
          class="group absolute inset-0 cursor-pointer rounded-[inherit] border-0 bg-transparent p-0 focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-primary"
          aria-label="Play video: AuthEndpoints intro"
          @click="play"
        >
          <span
            class="pointer-events-none absolute bottom-1 left-2 flex size-11 items-center justify-center rounded-full bg-primary text-inverted shadow-lg transition-transform group-hover:scale-105 motion-reduce:transition-none motion-reduce:group-hover:scale-100 sm:bottom-5 sm:left-5 sm:size-14"
            aria-hidden="true"
          >
            <UIcon
              name="i-lucide-play"
              class="ms-0.5 size-5 sm:size-7"
            />
          </span>
        </button>
      </div>
    </template>
  </UPageHero>
</template>
