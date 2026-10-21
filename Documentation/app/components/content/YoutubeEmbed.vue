<script setup lang="ts">
const props = defineProps<{
  id: string
  title: string
  /**
   * Thumbnail and play button until click. The iframe is inserted only then.
   */
  facade?: boolean
}>()

const playing = ref(false)
const frame = ref<HTMLIFrameElement | null>(null)
const thumbIndex = ref(0)

const allow = 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share'

const thumbnails = computed(() => [
  {
    src: `https://i.ytimg.com/vi/${props.id}/maxresdefault.jpg`,
    width: 1280,
    height: 720
  },
  {
    src: `https://i.ytimg.com/vi/${props.id}/hqdefault.jpg`,
    width: 480,
    height: 360
  }
])

const thumbnail = computed(() => {
  const sources = thumbnails.value
  return sources[thumbIndex.value] ?? sources[sources.length - 1]!
})

const showFrame = computed(() => !props.facade || playing.value)

const embedSrc = computed(() => {
  const src = `https://www.youtube-nocookie.com/embed/${props.id}`
  return props.facade ? `${src}?autoplay=1` : src
})

function useFallbackThumbnail() {
  if (thumbIndex.value === 0) {
    thumbIndex.value = 1
  }
}

function onThumbnailLoad(event: Event) {
  const image = event.currentTarget
  // YouTube returns a 120×90 placeholder JPEG (HTTP 200) when maxres is missing.
  if (image instanceof HTMLImageElement && image.naturalWidth > 0 && image.naturalWidth < 200) {
    useFallbackThumbnail()
  }
}

async function play() {
  playing.value = true
  await nextTick()
  frame.value?.focus()
}
</script>

<template>
  <div
    class="relative aspect-video w-full rounded-lg"
    :class="facade ? 'bg-elevated ring ring-default' : 'my-6 overflow-hidden'"
  >
    <div class="absolute inset-0 overflow-hidden rounded-[inherit]">
      <iframe
        v-if="showFrame"
        ref="frame"
        class="size-full border-0"
        :src="embedSrc"
        :title="title"
        :allow="allow"
        allowfullscreen
        :loading="facade ? undefined : 'lazy'"
        referrerpolicy="strict-origin-when-cross-origin"
      />
      <img
        v-else
        :src="thumbnail.src"
        alt=""
        :width="thumbnail.width"
        :height="thumbnail.height"
        loading="lazy"
        decoding="async"
        draggable="false"
        class="size-full object-cover"
        @error="useFallbackThumbnail"
        @load="onThumbnailLoad"
      >
    </div>

    <button
      v-if="facade && !playing"
      type="button"
      class="group absolute inset-0 cursor-pointer rounded-[inherit] border-0 bg-transparent p-0 focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-primary"
      :aria-label="`Play video: ${title}`"
      @click="play"
    >
      <span
        class="pointer-events-none absolute bottom-3 left-3 flex size-12 items-center justify-center rounded-full bg-primary text-inverted shadow-lg transition-transform group-hover:scale-105 motion-reduce:transition-none motion-reduce:group-hover:scale-100 sm:bottom-5 sm:left-5 sm:size-14"
        aria-hidden="true"
      >
        <UIcon
          name="i-lucide-play"
          class="ms-0.5 size-6 sm:size-7"
        />
      </span>
    </button>
  </div>
</template>
