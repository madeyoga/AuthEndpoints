import { joinURL } from 'ufo'
import {
  SITE_NAME,
  SITE_TITLE,
  SITE_DESCRIPTION,
  toCanonicalUrl
} from '#shared/site'

export function useDocsCanonical() {
  const route = useRoute()
  const canonical = computed(() => toCanonicalUrl(route.path))
  return { canonical }
}

export function useDocsSiteHead() {
  const { seo } = useAppConfig()
  const { app } = useRuntimeConfig()
  const { canonical } = useDocsCanonical()

  const favicon = computed(() => joinURL(app.baseURL, 'favicon.svg'))
  const sitemapHref = computed(() => joinURL(app.baseURL, 'sitemap.xml'))

  useHead({
    htmlAttrs: {
      lang: 'en'
    },
    titleTemplate: (titleChunk) => {
      if (!titleChunk || titleChunk === SITE_NAME || titleChunk === SITE_TITLE) {
        return SITE_TITLE
      }
      return `${titleChunk} - ${seo?.siteName || SITE_NAME}`
    },
    link: [
      { rel: 'icon', href: favicon, type: 'image/svg+xml' },
      { rel: 'canonical', href: canonical },
      { rel: 'sitemap', type: 'application/xml', title: 'Sitemap', href: sitemapHref }
    ]
  })

  useSeoMeta({
    ogSiteName: seo?.siteName || SITE_NAME,
    ogUrl: canonical,
    twitterCard: 'summary_large_image'
  })
}

export function useSoftwareJsonLd() {
  useHead({
    script: [{
      key: 'ld-json',
      type: 'application/ld+json',
      innerHTML: JSON.stringify({
        '@context': 'https://schema.org',
        '@type': ['SoftwareApplication', 'SoftwareSourceCode'],
        'name': SITE_NAME,
        'alternateName': SITE_TITLE,
        'description': SITE_DESCRIPTION,
        'url': toCanonicalUrl('/'),
        'applicationCategory': 'DeveloperApplication',
        'operatingSystem': 'ASP.NET Core',
        'programmingLanguage': 'C#',
        'runtimePlatform': '.NET 10',
        'license': 'https://opensource.org/licenses/MIT',
        'codeRepository': 'https://github.com/madeyoga/AuthEndpoints',
        'downloadUrl': 'https://www.nuget.org/packages/AuthEndpoints/',
        'isAccessibleForFree': true,
        'author': {
          '@type': 'Person',
          'name': 'madeyoga',
          'url': 'https://github.com/madeyoga'
        }
      })
    }]
  })
}

export function useTechArticleJsonLd(input: { title: string, description?: string }) {
  const route = useRoute()

  useHead(() => {
    const url = toCanonicalUrl(route.path)
    return {
      script: [{
        key: 'ld-json',
        type: 'application/ld+json',
        innerHTML: JSON.stringify({
          '@context': 'https://schema.org',
          '@type': 'TechArticle',
          'headline': input.title,
          'description': input.description,
          url,
          'mainEntityOfPage': url,
          'inLanguage': 'en',
          'isPartOf': {
            '@type': 'WebSite',
            'name': SITE_NAME,
            'url': toCanonicalUrl('/')
          },
          'about': {
            '@type': 'SoftwareApplication',
            'name': SITE_NAME,
            'url': toCanonicalUrl('/'),
            'downloadUrl': 'https://www.nuget.org/packages/AuthEndpoints/',
            'license': 'https://opensource.org/licenses/MIT'
          },
          'license': 'https://opensource.org/licenses/MIT'
        })
      }]
    }
  })
}
