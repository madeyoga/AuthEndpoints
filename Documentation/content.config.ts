import { defineContentConfig, defineCollection, z } from '@nuxt/content'

export default defineContentConfig({
  collections: {
    landing: defineCollection({
      type: 'page',
      source: 'index.md'
    }),
    docs: defineCollection({
      type: 'page',
      source: {
        include: '**',
        exclude: ['index.md', 'versions/**']
      },
      schema: z.object({
        links: z.array(z.object({
          label: z.string(),
          icon: z.string(),
          to: z.string(),
          target: z.string().optional()
        })).optional()
      })
    }),
    versions: defineCollection({
      type: 'page',
      source: 'versions/*.md',
      schema: z.object({
        title: z.string(),
        description: z.string(),
        date: z.string(),
        badge: z.string().optional(),
        tag: z.string().optional()
      })
    })
  }
})
