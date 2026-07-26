<script setup lang="ts">
const { isLoading } = useLoadingIndicator()

const appear = ref(false)
const appeared = ref(false)

onMounted(() => {
  setTimeout(() => {
    appear.value = true
    setTimeout(() => {
      appeared.value = true
    }, 1000)
  }, 0)
})
</script>

<template>
  <div
    class="absolute inset-0 w-full -top-px transition-all text-primary shrink-0 overflow-hidden pointer-events-none"
    :class="[
      isLoading ? 'animate-pulse' : (appear ? '' : 'opacity-0'),
      appeared ? 'duration-[400ms]' : 'duration-1000'
    ]"
  >
    <!-- Soft teal radial wash -->
    <div
      class="absolute inset-0 opacity-40 dark:opacity-30"
      style="background: radial-gradient(ellipse 80% 50% at 50% -20%, color-mix(in oklab, var(--ui-primary) 35%, transparent), transparent 70%);"
    />
    <!-- Faint grid -->
    <div
      class="absolute inset-0 opacity-[0.07] dark:opacity-[0.12]"
      style="background-image: linear-gradient(color-mix(in oklab, var(--ui-primary) 50%, transparent) 1px, transparent 1px), linear-gradient(90deg, color-mix(in oklab, var(--ui-primary) 50%, transparent) 1px, transparent 1px); background-size: 48px 48px; mask-image: linear-gradient(to bottom, black 0%, transparent 70%);"
    />
    <svg
      viewBox="0 0 1440 181"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      class="pointer-events-none relative w-full"
    >
      <mask
        id="path-1-inside-1_414_5526"
        fill="white"
      >
        <path d="M0 0H1440V181H0V0Z" />
      </mask>
      <path
        d="M0 0H1440V181H0V0Z"
        fill="url(#paint0_linear_414_5526)"
        fill-opacity="0.22"
      />
      <path
        d="M0 2H1440V-2H0V2Z"
        fill="url(#paint1_linear_414_5526)"
        mask="url(#path-1-inside-1_414_5526)"
      />
      <defs>
        <linearGradient
          id="paint0_linear_414_5526"
          x1="720"
          y1="0"
          x2="720"
          y2="181"
          gradientUnits="userSpaceOnUse"
        >
          <stop stop-color="currentColor" />
          <stop
            offset="1"
            stop-color="currentColor"
            stop-opacity="0"
          />
        </linearGradient>
        <linearGradient
          id="paint1_linear_414_5526"
          x1="0"
          y1="90.5"
          x2="1440"
          y2="90.5"
          gradientUnits="userSpaceOnUse"
        >
          <stop
            stop-color="currentColor"
            stop-opacity="0"
          />
          <stop
            offset="0.395"
            stop-color="currentColor"
          />
          <stop
            offset="1"
            stop-color="currentColor"
            stop-opacity="0"
          />
        </linearGradient>
      </defs>
    </svg>
  </div>
</template>
