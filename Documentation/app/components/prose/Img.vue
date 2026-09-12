<script setup lang="ts">
import { joinURL, withLeadingSlash, withTrailingSlash } from 'ufo'

const props = defineProps<{
  src: string
  alt?: string
  width?: string | number
  height?: string | number
}>()

const baseURL = useRuntimeConfig().app.baseURL
const src = computed(() => {
  if (props.src?.startsWith('/') && !props.src.startsWith('//')) {
    const base = withLeadingSlash(withTrailingSlash(baseURL))
    if (base !== '/' && !props.src.startsWith(base)) {
      return joinURL(base, props.src)
    }
  }
  return props.src
})
</script>

<template>
  <img
    :src="src"
    :alt="props.alt"
    :width="props.width"
    :height="props.height"
  >
</template>
