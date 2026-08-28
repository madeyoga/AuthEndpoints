/** Public GitHub Pages origin for the library docs (project site under /AuthEndpoints/). */
export const DOCS_ORIGIN = 'https://madeyoga.github.io'
export const DOCS_BASE_PATH = '/AuthEndpoints'
export const DOCS_SITE_URL = `${DOCS_ORIGIN}${DOCS_BASE_PATH}`

export const SITE_NAME = 'AuthEndpoints'
export const SITE_TITLE = 'AuthEndpoints — ASP.NET Core Identity auth library'
export const SITE_DESCRIPTION = 'Ready-made ASP.NET Core Identity auth endpoints for web and mobile clients — cookies, JWT, passkeys, and composable modules.'

const OWN_URL_PREFIXES = [
  DOCS_SITE_URL,
  `${DOCS_ORIGIN}${DOCS_BASE_PATH}/`,
  'https://github.com/madeyoga/AuthEndpoints',
  'https://www.nuget.org/packages/AuthEndpoints',
  'https://nuget.org/packages/AuthEndpoints'
] as const

/**
 * Links that should not get rel=nofollow: this docs site, the GitHub repo/releases,
 * and the NuGet package page. Unrelated externals can keep nofollow.
 */
export function isOwnPropertyHref(href: string | undefined | null): boolean {
  if (!href) {
    return false
  }

  const trimmed = href.trim()
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('mailto:') || trimmed.startsWith('tel:')) {
    return true
  }

  // In-app paths (including the Pages base URL) are first-party.
  if (trimmed.startsWith('/') && !trimmed.startsWith('//')) {
    return true
  }

  return OWN_URL_PREFIXES.some((prefix) => {
    const normalized = prefix.replace(/\/$/, '')
    return trimmed === normalized
      || trimmed === `${normalized}/`
      || trimmed.startsWith(`${normalized}/`)
      || trimmed.startsWith(`${normalized}?`)
      || trimmed.startsWith(`${normalized}#`)
  })
}

/** Drop a leading /AuthEndpoints prefix so canonicals can be built from route.path or request URLs. */
export function stripDocsBasePath(path: string): string {
  const pathname = path.split('?')[0]?.split('#')[0] || '/'
  if (pathname === DOCS_BASE_PATH || pathname === `${DOCS_BASE_PATH}/`) {
    return '/'
  }
  if (pathname.startsWith(`${DOCS_BASE_PATH}/`)) {
    return pathname.slice(DOCS_BASE_PATH.length) || '/'
  }
  return pathname.startsWith('/') ? pathname : `/${pathname}`
}

function isFilePath(path: string): boolean {
  const last = path.split('/').pop() || ''
  return last.includes('.')
}

/** Absolute trailing-slash URL on the public docs host. */
export function toCanonicalUrl(path: string): string {
  const hashIndex = path.indexOf('#')
  const hash = hashIndex >= 0 ? path.slice(hashIndex) : ''
  const withoutHash = hashIndex >= 0 ? path.slice(0, hashIndex) : path
  const pathname = stripDocsBasePath(withoutHash.split('?')[0] || '/')

  if (pathname === '/' || pathname === '') {
    return `${DOCS_SITE_URL}/${hash}`
  }

  if (isFilePath(pathname)) {
    return `${DOCS_SITE_URL}${pathname}${hash}`
  }

  const withSlash = pathname.endsWith('/') ? pathname : `${pathname}/`
  return `${DOCS_SITE_URL}${withSlash}${hash}`
}

export function withNavTrailingSlash(path: string | undefined | null): string | undefined {
  if (!path) {
    return path ?? undefined
  }
  if (path.startsWith('http://') || path.startsWith('https://') || path.startsWith('mailto:') || path.startsWith('#')) {
    return path
  }
  const hashIndex = path.indexOf('#')
  const hash = hashIndex >= 0 ? path.slice(hashIndex) : ''
  const pathname = hashIndex >= 0 ? path.slice(0, hashIndex) : path
  if (isFilePath(pathname) || pathname === '/') {
    return `${pathname}${hash}`
  }
  return `${pathname.endsWith('/') ? pathname : `${pathname}/`}${hash}`
}

export function applyTrailingSlashToNav<T extends { path?: string, to?: unknown, children?: T[] }>(
  items: T[] | undefined | null
): T[] {
  if (!items?.length) {
    return []
  }

  return items.map((item) => {
    const next = { ...item }
    if (typeof next.path === 'string') {
      next.path = withNavTrailingSlash(next.path)
    }
    if (typeof next.to === 'string') {
      next.to = withNavTrailingSlash(next.to)
    }
    if (next.children?.length) {
      next.children = applyTrailingSlashToNav(next.children)
    }
    return next
  })
}

export function sitemapLocs(paths: Iterable<string>): string[] {
  const unique = new Set<string>()
  for (const path of paths) {
    unique.add(toCanonicalUrl(path).split('#')[0]!)
  }
  return [...unique].sort((a, b) => a.localeCompare(b))
}
