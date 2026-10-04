/**
 * Pages that moved in the docs restructure. Keys are old content paths (no trailing slash).
 * Values are new content paths, optionally with a #fragment.
 *
 * GitHub Pages has no server redirects and Nitro prerender skips 3xx responses, so each old
 * path is prerendered as a small page with a meta refresh (see app/pages/[...slug].vue).
 * nuxt.config.ts adds every key to nitro.prerender.routes.
 */
export const DOCS_REDIRECTS: Readonly<Record<string, string>> = {
  '/examples': '/guides',
  '/examples/register-confirmed-account': '/guides/registration',
  '/examples/passkey-sign-in': '/guides/sign-in#sign-in-with-a-passkey',
  '/examples/two-factor': '/guides/two-factor',
  '/examples/reset-forgotten-password': '/guides/reset-password',
  '/examples/reauth': '/guides/step-up',
  '/getting-started/production': '/guides/production',
  '/getting-started/configuration': '/modules/configuration',
  '/getting-started/compare': '/concepts/compare',
  '/getting-started/stock-identity-vs-authendpoints': '/concepts/stock-identity-vs-authendpoints',
  '/getting-started/faq': '/concepts/faq'
}

/** Returns the new path for a moved page, or undefined. Accepts a content path or a route path. */
export function findDocsRedirect(contentPath: string): string | undefined {
  return DOCS_REDIRECTS[contentPath]
}
