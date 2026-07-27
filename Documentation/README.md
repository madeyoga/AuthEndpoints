# AuthEndpoints Documentation

Nuxt Content site for the [AuthEndpoints](https://github.com/madeyoga/AuthEndpoints) library — getting started, composable endpoints, and module reference.

**Live site:** [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/)

Content lives under [`content/`](content/). The site is built with [Nuxt](https://nuxt.com), [Nuxt UI](https://ui.nuxt.com), and [Nuxt Content](https://content.nuxt.com). GitHub Actions deploys from `main` via [`.github/workflows/docs.yml`](../.github/workflows/docs.yml).

## Setup

```bash
pnpm install
```

## Development

```bash
pnpm dev
```

Open `http://localhost:3000`.

## Production

Generate the static GitHub Pages build (project site base path):

```bash
# Windows PowerShell
$env:NUXT_APP_BASE_URL="/AuthEndpoints/"; pnpm generate

# bash
NUXT_APP_BASE_URL=/AuthEndpoints/ pnpm generate
```

Or for a local Node preview without the Pages base path:

```bash
pnpm build
pnpm preview
```
