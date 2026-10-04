<script setup lang="ts">
import type { ContentNavigationItem } from '@nuxt/content'
import { findPageHeadline } from '@nuxt/content/utils'
import { toContentPath } from '#shared/site'
import { findDocsRedirect } from '#shared/redirects'

definePageMeta({
  layout: 'docs'
})

const route = useRoute()
const { toc } = useAppConfig()
const navigation = inject<Ref<ContentNavigationItem[]>>('navigation')

const contentPath = computed(() => toContentPath(route.path))
// Moved pages render a meta-refresh stub instead of a 404 (static hosting has no redirects).
const redirectTo = findDocsRedirect(contentPath.value)

const { data: page } = await useAsyncData(
  () => contentPath.value,
  () => redirectTo ? Promise.resolve(null) : queryCollection('docs').path(contentPath.value).first()
)
if (!page.value && !redirectTo) {
  throw createError({ statusCode: 404, statusMessage: 'Page not found', fatal: true })
}

const { data: surround } = await useAsyncData(
  () => `${contentPath.value}-surround`,
  () => redirectTo
    ? Promise.resolve([])
    : queryCollectionItemSurroundings('docs', contentPath.value, {
        fields: ['description']
      })
)

const headline = computed(() => findPageHeadline(navigation?.value, page.value?.path))

if (redirectTo) {
  useDocsRedirect(redirectTo)
} else if (page.value) {
  const title = page.value.seo?.title || page.value.title
  const description = page.value.seo?.description || page.value.description

  useSeoMeta({
    title,
    ogTitle: title,
    description,
    ogDescription: description,
    ogType: 'article'
  })

  useTechArticleJsonLd({ title, description })

  defineOgImage('Docs', { title, description, headline: headline.value })
}

const links = computed(() => {
  const links = []
  if (toc?.bottom?.edit) {
    links.push({
      icon: 'i-lucide-external-link',
      label: 'Edit this page',
      to: `${toc.bottom.edit}/${page?.value?.stem}.${page?.value?.extension}`,
      target: '_blank'
    })
  }

  return [...links, ...(toc?.bottom?.links || [])].filter(Boolean)
})
</script>

<template>
  <DocsRedirectNotice
    v-if="redirectTo"
    :to="redirectTo"
  />
  <UPage v-else-if="page">
    <UPageHeader
      :title="page.title"
      :description="page.description"
      :headline="headline"
    >
      <template #links>
        <UButton
          v-for="(link, index) in page.links"
          :key="index"
          v-bind="link"
        />

        <PageHeaderLinks />
      </template>
    </UPageHeader>

    <UPageBody>
      <ContentRenderer
        v-if="page"
        :value="page"
      />

      <USeparator v-if="surround?.length" />

      <UContentSurround :surround="surround" />
    </UPageBody>

    <template
      v-if="page?.body?.toc?.links?.length"
      #right
    >
      <UContentToc
        :title="toc?.title"
        :links="page.body?.toc?.links"
      >
        <template
          v-if="toc?.bottom"
          #bottom
        >
          <div
            class="hidden lg:block space-y-6"
            :class="{ 'mt-6!': page.body?.toc?.links?.length }"
          >
            <USeparator
              v-if="page.body?.toc?.links?.length"
              type="dashed"
            />

            <UPageLinks
              :title="toc.bottom.title"
              :links="links"
            />
          </div>
        </template>
      </UContentToc>
    </template>
  </UPage>
</template>
