import { visit } from 'unist-util-visit'
import { isOwnPropertyHref, toCanonicalUrl, DOCS_SITE_URL, DOCS_BASE_PATH } from '../shared/site'

interface HastElement {
  type: string
  tagName?: string
  properties?: {
    href?: unknown
    rel?: unknown
    [key: string]: unknown
  }
}

function relList(value: unknown): string[] {
  if (!value) {
    return []
  }
  if (Array.isArray(value)) {
    return value.map(String).flatMap(part => part.split(/\s+/)).filter(Boolean)
  }
  return String(value).split(/\s+/).filter(Boolean)
}

function toInternalDocsPath(href: string): string | undefined {
  if (href.startsWith(DOCS_SITE_URL)) {
    const rest = href.slice(DOCS_SITE_URL.length) || '/'
    return rest.startsWith('/') ? rest : `/${rest}`
  }
  if (href.startsWith(DOCS_BASE_PATH + '/') || href === DOCS_BASE_PATH) {
    const rest = href.slice(DOCS_BASE_PATH.length) || '/'
    return rest.startsWith('/') ? rest : `/${rest}`
  }
  return undefined
}

/**
 * Keep rel=nofollow on unrelated externals, but drop it on first-party docs,
 * GitHub repo/releases, and the NuGet package page. Also rewrite absolute
 * github.io docs URLs to in-app paths so they pick up trailing slashes.
 */
export default function rehypeOwnPropertyLinks() {
  return (tree: unknown) => {
    visit(tree as never, 'element', (node: HastElement) => {
      if (node.tagName !== 'a' || !node.properties) {
        return
      }

      const href = typeof node.properties.href === 'string' ? node.properties.href : ''
      if (!href || !isOwnPropertyHref(href)) {
        return
      }

      const internal = toInternalDocsPath(href)
      if (internal) {
        const canonical = toCanonicalUrl(internal)
        const path = canonical.slice(DOCS_SITE_URL.length) || '/'
        node.properties.href = path
      }

      const nextRel = relList(node.properties.rel).filter(token => token !== 'nofollow')
      if (nextRel.length) {
        node.properties.rel = nextRel
      } else {
        delete node.properties.rel
      }
    })
  }
}
