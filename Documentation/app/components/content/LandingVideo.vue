<script setup lang="ts">
defineProps<{
  id: string
  title: string
}>()
</script>

<template>
  <UPageSection
    class="dark:bg-zinc-950"
    :ui="{ container: 'py-0 sm:py-0 lg:py-0' }"
  >
    <div class="mx-auto w-full max-w-6xl">
      <YoutubeEmbed
        :id="id"
        :title="title"
        facade
      />
    </div>
  </UPageSection>
</template>
