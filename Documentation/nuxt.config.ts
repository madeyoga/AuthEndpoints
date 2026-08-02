// https://nuxt.com/docs/api/configuration/nuxt-config
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
        }
      }
    },
    experimental: {
      sqliteConnector: 'native'
    }
  },

  experimental: {
    asyncContext: true
  },

  compatibilityDate: '2026-06-30',

  nitro: {
    preset: 'github-pages',
    prerender: {
      routes: [
        '/',
        '/changelog'
      ],
      crawlLinks: true
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
