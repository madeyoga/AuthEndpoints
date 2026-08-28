import { queryCollection } from '@nuxt/content/server'
import { sitemapLocs, isPublicDocsPath } from '#shared/site'

export default defineEventHandler(async (event) => {
  const docs = await queryCollection(event, 'docs').select('path').all()
  const locs = sitemapLocs([
    '/',
    '/changelog',
    ...docs.map(page => page.path).filter((path): path is string => Boolean(path) && isPublicDocsPath(path))
  ])

  const body = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...locs.map(loc => `  <url>\n    <loc>${loc}</loc>\n  </url>`),
    '</urlset>',
    ''
  ].join('\n')

  setHeader(event, 'Content-Type', 'application/xml; charset=utf-8')
  return body
})
