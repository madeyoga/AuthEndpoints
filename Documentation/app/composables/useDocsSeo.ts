import { joinURL } from 'ufo'
import {
  SITE_NAME,
  SITE_TITLE,
  SITE_DESCRIPTION,
  toCanonicalUrl,
  toContentPath,
  withNavTrailingSlash
} from '#shared/site'
import { findDocsRedirect } from '#shared/redirects'

export function useDocsCanonical() {
  const route = useRoute()
  // A moved page points its canonical link at the new URL.
  const canonical = computed(() => toCanonicalUrl(findDocsRedirect(toContentPath(route.path)) ?? route.path))
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

/**
 * Head tags for a moved page: meta refresh to the new URL, noindex, and a client-side
 * replace for in-app navigation. The canonical link already points at the new URL
 * (see useDocsCanonical).
 */
export function useDocsRedirect(to: string) {
  const { app } = useRuntimeConfig()
  const target = withNavTrailingSlash(to) || '/'
  const href = joinURL(app.baseURL, target)

  useHead({
    meta: [{ 'http-equiv': 'refresh', 'content': `0; url=${href}` }]
  })
  useSeoMeta({
    title: 'Page moved',
    description: `This page moved to ${toCanonicalUrl(target)}`,
    robots: 'noindex, follow'
  })

  onMounted(() => {
    navigateTo(target, { replace: true })
  })
}
