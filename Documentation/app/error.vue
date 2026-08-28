<script setup lang="ts">
import type { NuxtError } from '#app'
import { joinURL } from 'ufo'

const props = defineProps<{
  error: NuxtError
}>()

const { app } = useRuntimeConfig()

useHead({
  htmlAttrs: {
    lang: 'en'
  },
  titleTemplate: '%s',
  link: [
    { rel: 'icon', href: joinURL(app.baseURL, 'favicon.svg'), type: 'image/svg+xml' }
  ]
})

useSeoMeta({
  title: 'Page not found',
  description: 'This documentation page does not exist.',
  robots: 'noindex, nofollow'
})

const { data: navigation } = await useAsyncData('navigation', () => queryCollectionNavigation('docs'))
const { data: files } = useLazyAsyncData('search', () => queryCollectionSearchSections('docs'), {
  server: false
})

const displayError = computed(() => ({
  statusCode: props.error?.statusCode || 404,
  statusMessage: props.error?.statusMessage || 'Page not found',
  message: props.error?.message && props.error.message !== props.error.statusMessage
    ? props.error.message
    : 'This documentation page does not exist.'
}))

provide('navigation', navigation)
</script>

<template>
  <UApp>
    <AppHeader />

    <UError
      :error="displayError"
      redirect="/"
      :clear="{ label: 'Docs home', size: 'lg' }"
    />

    <AppFooter />

    <ClientOnly>
      <LazyUContentSearch
        :files="files"
        :navigation="navigation"
      />
    </ClientOnly>
  </UApp>
</template>
