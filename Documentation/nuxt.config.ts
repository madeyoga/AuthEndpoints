// https://nuxt.com/docs/api/configuration/nuxt-config
import rehypeOwnPropertyLinks from './rehype/own-property-links'
import { isOwnPropertyHref } from './shared/site'

export default defineNuxtConfig({
  modules: [
    '@nuxt/eslint',
    '@nuxt/image',
    '@nuxt/ui',
    '@nuxt/content',
    'nuxt-og-image',
    'nuxt-llms',
    '@nuxtjs/mcp-toolkit'
  ],

  devtools: {
    enabled: true
  },

  app: {
    // CI sets NUXT_APP_BASE_URL=/AuthEndpoints/ for GitHub Pages project site.
    baseURL: process.env.NUXT_APP_BASE_URL || '/'
  },

  css: ['~/assets/css/main.css'],

  site: {
    // Origin only — nuxt-site-config / og-image append app.baseURL (/AuthEndpoints/).
    url: 'https://madeyoga.github.io',
    name: 'AuthEndpoints',
    trailingSlash: true,
    indexable: true
  },

  content: {
    build: {
      markdown: {
        toc: {
          searchDepth: 1
        },
        highlight: {
          // Defaults are json/js/ts/html/css/vue/shell/mdc/md/yaml only.
          // bash works via the shell grammar; csharp must be loaded explicitly.
          langs: [
            'json',
            // 'js',
            // 'ts',
            // 'html',
            // 'css',
            // 'vue',
            // 'shell',
            // 'mdc',
            // 'md',
            // 'yaml',
            'bash',
            'csharp',
            'cs'
          ]
        },
        rehypePlugins: {
          'rehype-external-links': {
            options: {
              rel(node: { properties?: { href?: unknown } }) {
                const href = typeof node.properties?.href === 'string' ? node.properties.href : ''
                if (isOwnPropertyHref(href)) {
                  return []
                }
                return ['nofollow']
              }
            }
          },
          'rehype-own-property-links': {
            instance: rehypeOwnPropertyLinks
          }
        }
      }
    },
    experimental: {
      sqliteConnector: 'native'
    }
  },

  routeRules: {
    '/sitemap.xml': { prerender: true }
  },

  experimental: {
    asyncContext: true,
    defaults: {
      nuxtLink: {
        trailingSlash: 'append'
      }
    }
  },

  compatibilityDate: '2026-06-30',

  nitro: {
    preset: 'github-pages',
    prerender: {
      routes: [
        '/',
        '/changelog',
        '/sitemap.xml',
        '/404'
      ],
      crawlLinks: true
    }
  },

  hooks: {
    'nitro:init'(nitro) {
      nitro.hooks.hook('prerender:done', async () => {
        const { copyFile, rm } = await import('node:fs/promises')
        const { join } = await import('node:path')
        const publicDir = nitro.options.output.publicDir
        // github-pages emits an empty SPA 404.html; replace it with the prerendered error page
        // and drop /404/ so that path is also a real HTTP 404 on Pages.
        await copyFile(join(publicDir, '404/index.html'), join(publicDir, '404.html'))
        await rm(join(publicDir, '404'), { recursive: true, force: true })
      })
    }
  },

  eslint: {
    config: {
      stylistic: {
        commaDangle: 'never',
        braceStyle: '1tbs'
      }
    }
  },

  llms: {
    domain: 'https://madeyoga.github.io/AuthEndpoints',
    title: 'AuthEndpoints',
    description: 'ASP.NET Core library of ready-made Identity auth endpoints for web and mobile clients — cookies, JWT, passkeys, and composable modules.',
    full: {
      title: 'AuthEndpoints - Full Documentation',
      description: 'Complete documentation for AuthEndpoints: getting started, composable endpoints, and module reference.'
    },
    sections: [
      {
        title: 'Getting Started',
        contentCollection: 'docs',
        contentFilters: [
          { field: 'path', operator: 'LIKE', value: '/getting-started%' }
        ]
      },
      {
        title: 'Composable Endpoints',
        contentCollection: 'docs',
        contentFilters: [
          { field: 'path', operator: 'LIKE', value: '/composables%' }
        ]
      },
      {
        title: 'Modules',
        contentCollection: 'docs',
        contentFilters: [
          { field: 'path', operator: 'LIKE', value: '/modules%' }
        ]
      },
      {
        title: 'Changelog',
        contentCollection: 'versions',
        contentFilters: []
      }
    ]
  },

  mcp: {
    name: 'AuthEndpoints docs'
  },

  ogImage: {
    zeroRuntime: true
  }
})
