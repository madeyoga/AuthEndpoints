<script setup lang="ts">
import { withNavTrailingSlash } from '#shared/site'

const props = defineProps<{ to: string }>()
const target = computed(() => withNavTrailingSlash(props.to) || '/')
</script>

<template>
  <UPage>
    <UPageHeader
      title="This page moved"
      :description="`The new location is ${target}.`"
    />
    <UPageBody>
      <p>
        <ULink
          :to="target"
          class="text-primary"
        >
          Go to the new page
        </ULink>
      </p>
    </UPageBody>
  </UPage>
</template>
