<script setup lang="ts">
const { data: page } = await useAsyncData('index', () => queryCollection('landing').path('/').first())
if (!page.value) {
  throw createError({ statusCode: 404, statusMessage: 'Page not found', fatal: true })
}

const { data: releases } = await useAsyncData('index-releases', () =>
  queryCollection('versions').order('date', 'DESC').select('tag').all()
)
const version = releases.value
  ?.map(release => release.tag?.replace(/^v/, ''))
  .find(tag => tag && /^\d+\.\d+\.\d+$/.test(tag))

const title = page.value.seo?.title || page.value.title
const description = page.value.seo?.description || page.value.description

useSeoMeta({
  title,
  ogTitle: title,
  description,
  ogDescription: description,
  ogType: 'website'
})

defineOgImage('Docs', {
  title: 'AuthEndpoints',
  description,
  headline: 'ASP.NET Core'
})

useSoftwareJsonLd(version)
</script>

<template>
  <ContentRenderer
    v-if="page"
    :value="page"
    :prose="false"
  />
</template>
