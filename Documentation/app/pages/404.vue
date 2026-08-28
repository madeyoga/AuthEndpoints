<script setup lang="ts">
useSeoMeta({
  title: 'Page not found',
  description: 'This documentation page does not exist.',
  robots: 'noindex, nofollow'
})
</script>

<template>
  <UError
    :error="{
      statusCode: 404,
      statusMessage: 'Page not found',
      message: 'This documentation page does not exist.'
    }"
    redirect="/"
    :clear="{ label: 'Docs home', size: 'lg' }"
  />
</template>
