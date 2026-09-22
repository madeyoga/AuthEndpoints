<script setup lang="ts">
defineProps<{
  id: string
  title: string
}>()
</script>

<template>
  <div class="relative my-6 aspect-video w-full overflow-hidden rounded-lg">
    <iframe
      class="absolute inset-0 size-full border-0"
      :src="`https://www.youtube-nocookie.com/embed/${id}`"
      :title="title"
      allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
      allowfullscreen
      loading="lazy"
      referrerpolicy="strict-origin-when-cross-origin"
    />
  </div>
</template>
