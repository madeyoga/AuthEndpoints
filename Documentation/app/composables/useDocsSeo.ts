import { joinURL } from 'ufo'
import {
  SITE_NAME,
  SITE_TITLE,
  SITE_DESCRIPTION,
  REPOSITORY_URL,
  NUGET_URL,
  LICENSE_URL,
  toCanonicalUrl,
  toContentPath,
  withNavTrailingSlash
} from '#shared/site'
import { findDocsRedirect } from '#shared/redirects'

const TWITTER_META_KEY = 'docs:twitter-meta'

interface ResolvedHeadTag {
  tag: string
  props: Record<string, unknown>
}

function metaContent(tags: ResolvedHeadTag[], id: string): string | undefined {
  for (let index = tags.length - 1; index >= 0; index--) {
    const tag = tags[index]
    if (tag?.tag !== 'meta') {
      continue
    }
    const key = tag.props.property || tag.props.name
    if (key !== id) {
      continue
    }
    const content = tag.props.content
    return typeof content === 'string' && content ? content : undefined
  }
  return undefined
}

function upsertNamedMeta(tags: ResolvedHeadTag[], name: string, content: string | undefined) {
  if (!content) {
    return
  }
  const existing = tags.find(tag => tag.tag === 'meta' && tag.props.name === name)
  if (existing) {
    existing.props.content = content
    return
  }
  tags.push({
    tag: 'meta',
    props: { name, content }
  })
}

/** Canonical URLs must not include a fragment. Redirect targets may still use one. */
function withoutUrlFragment(url: string): string {
  const hashIndex = url.indexOf('#')
  return hashIndex === -1 ? url : url.slice(0, hashIndex)
}

export function useDocsTwitterMeta() {
  const head = injectHead()
  if (head.plugins.has(TWITTER_META_KEY)) {
    return
  }

  // Pages set og:title and description themselves. Copy them once, after resolve,
  // so every page gets twitter:title and twitter:description without per-page tags.
  head.use({
    key: TWITTER_META_KEY,
    hooks: {
      'tags:afterResolve': (ctx: { tags: ResolvedHeadTag[] }) => {
        upsertNamedMeta(ctx.tags, 'twitter:title', metaContent(ctx.tags, 'og:title'))
        upsertNamedMeta(ctx.tags, 'twitter:description', metaContent(ctx.tags, 'description'))
      }
    }
  })
}

export function useDocsCanonical() {
  const route = useRoute()
  // A moved page points its canonical link at the new URL, without any #fragment.
  const canonical = computed(() => withoutUrlFragment(toCanonicalUrl(findDocsRedirect(toContentPath(route.path)) ?? route.path)))
  return { canonical }
}

export function useDocsSiteHead() {
  useDocsTwitterMeta()

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

export function useSoftwareJsonLd(version?: string) {
  const url = toCanonicalUrl('/')
  const author = {
    '@type': 'Person',
    'name': 'madeyoga',
    'url': 'https://github.com/madeyoga'
  }

  useHead({
    script: [{
      key: 'ld-json',
      type: 'application/ld+json',
      innerHTML: JSON.stringify({
        '@context': 'https://schema.org',
        '@graph': [
          {
            '@type': 'SoftwareApplication',
            '@id': `${url}#software`,
            'name': SITE_NAME,
            'alternateName': SITE_TITLE,
            'description': SITE_DESCRIPTION,
            url,
            'applicationCategory': 'DeveloperApplication',
            'operatingSystem': 'ASP.NET Core',
            'softwareVersion': version,
            'license': LICENSE_URL,
            'downloadUrl': NUGET_URL,
            'installUrl': NUGET_URL,
            'isAccessibleForFree': true,
            'offers': {
              '@type': 'Offer',
              'price': '0',
              'priceCurrency': 'USD'
            },
            author
          },
          {
            '@type': 'SoftwareSourceCode',
            '@id': `${url}#source`,
            'name': SITE_NAME,
            'description': SITE_DESCRIPTION,
            url,
            'codeRepository': REPOSITORY_URL,
            'programmingLanguage': 'C#',
            'runtimePlatform': '.NET 10',
            'version': version,
            'license': LICENSE_URL,
            'targetProduct': { '@id': `${url}#software` },
            author
          }
        ]
      })
    }]
  })
}

type MinimarkNode = string | [string, Record<string, unknown>, ...MinimarkNode[]]

function minimarkText(node: MinimarkNode): string {
  if (typeof node === 'string') {
    return node
  }
  const [, , ...children] = node
  return children.map(minimarkText).join('')
}

export function faqEntriesFromBody(body: { value?: unknown } | undefined | null) {
  const nodes = Array.isArray(body?.value) ? body.value as MinimarkNode[] : []
  const entries: { question: string, answer: string }[] = []
  let current: { question: string, parts: string[] } | undefined

  const flush = () => {
    const answer = current?.parts.join(' ').replace(/\s+/g, ' ').trim()
    if (current && answer) {
      entries.push({ question: current.question, answer })
    }
    current = undefined
  }

  for (const node of nodes) {
    if (Array.isArray(node) && node[0] === 'h2') {
      flush()
      const question = minimarkText(node).trim()
      if (question.endsWith('?')) {
        current = { question, parts: [] }
      }
    } else if (current) {
      current.parts.push(minimarkText(node))
    }
  }
  flush()
  return entries
}

export function useFaqPageJsonLd(body: { value?: unknown } | undefined | null) {
  const route = useRoute()
  const entries = faqEntriesFromBody(body)
  if (!entries.length) {
    return
  }

  useHead(() => ({
    script: [{
      key: 'ld-json-faq',
      type: 'application/ld+json',
      innerHTML: JSON.stringify({
        '@context': 'https://schema.org',
        '@type': 'FAQPage',
        'url': toCanonicalUrl(route.path),
        'mainEntity': entries.map(entry => ({
          '@type': 'Question',
          'name': entry.question,
          'acceptedAnswer': {
            '@type': 'Answer',
            'text': entry.answer
          }
        }))
      })
    }]
  }))
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
            'downloadUrl': NUGET_URL,
            'license': LICENSE_URL
          },
          'license': LICENSE_URL
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
