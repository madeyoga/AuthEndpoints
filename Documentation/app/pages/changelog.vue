<script setup lang="ts">
const { data: versions } = await useAsyncData('changelog-versions', () =>
  queryCollection('versions').order('date', 'DESC').all()
)

const title = 'Changelog'
const description = 'Release notes for AuthEndpoints — Identity auth endpoints for ASP.NET Core.'

useSeoMeta({
  title,
  description,
  ogTitle: 'Changelog - AuthEndpoints',
  ogDescription: description,
  ogType: 'article'
})

defineOgImage('Docs', {
  title,
  description,
  headline: 'Releases'
})

useTechArticleJsonLd({ title, description })

function releaseUrl(version: { tag?: string, title?: string }) {
  const tag = version.tag || version.title
  return `https://github.com/madeyoga/AuthEndpoints/releases/tag/${tag}`
}

function badgeProps(badge?: string) {
  if (!badge) {
    return undefined
  }

  const color = badge === 'Latest'
    ? 'primary'
    : badge === 'RC' || badge === 'Preview'
      ? 'warning'
      : 'neutral'

  return {
    label: badge,
    color: color as 'primary' | 'warning' | 'neutral',
    variant: 'subtle' as const
  }
}
</script>

<template>
  <div>
    <UPageHero
      title="Changelog"
      description="Release notes for AuthEndpoints. Each entry summarizes what shipped; full notes and assets live on GitHub Releases."
      :links="[{
        label: 'GitHub Releases',
        to: 'https://github.com/madeyoga/AuthEndpoints/releases',
        target: '_blank',
        icon: 'i-simple-icons-github',
        color: 'neutral',
        variant: 'outline',
        size: 'lg'
      }, {
        label: 'Get started',
        to: '/getting-started/',
        trailingIcon: 'i-lucide-arrow-right',
        size: 'lg'
      }]"
    />

    <UContainer>
      <div class="flex flex-wrap items-center gap-3 pb-8">
        <a
          href="https://www.nuget.org/packages/AuthEndpoints/"
          target="_blank"
          rel="noopener noreferrer"
        >
          <img
            alt="AuthEndpoints on NuGet"
            src="https://img.shields.io/nuget/v/AuthEndpoints?label=AuthEndpoints&logo=NuGet&style=flat-square"
          >
        </a>
        <a
          href="https://www.nuget.org/packages/AuthEndpoints.External.OAuth/"
          target="_blank"
          rel="noopener noreferrer"
        >
          <img
            alt="AuthEndpoints.External.OAuth on NuGet"
            src="https://img.shields.io/nuget/vpre/AuthEndpoints.External.OAuth?label=External.OAuth&logo=NuGet&style=flat-square"
          >
        </a>
      </div>
      <UPageBody class="pb-24">
        <UChangelogVersions v-if="versions?.length">
          <UChangelogVersion
            v-for="version in versions"
            :key="version.path"
            :title="version.title"
            :description="version.description"
            :date="version.date"
            :badge="badgeProps(version.badge)"
            :to="releaseUrl(version)"
            target="_blank"
          >
            <template
              v-if="version.body"
              #body
            >
              <ContentRenderer
                :value="version"
                class="prose prose-sm dark:prose-invert max-w-none"
              />
            </template>

            <template #footer>
              <UButton
                :to="releaseUrl(version)"
                target="_blank"
                label="Full release"
                icon="i-simple-icons-github"
                color="neutral"
                variant="ghost"
                size="sm"
                trailing-icon="i-lucide-arrow-up-right"
              />
            </template>
          </UChangelogVersion>
        </UChangelogVersions>

        <UEmpty
          v-else
          icon="i-lucide-scroll-text"
          title="No releases yet"
          description="Version notes will appear here when content is added under content/versions/."
        />
      </UPageBody>
    </UContainer>
  </div>
</template>
