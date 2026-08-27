# AuthEndpoints Documentation

Nuxt Content site for the [AuthEndpoints](https://github.com/madeyoga/AuthEndpoints) library — getting started, composable endpoints, and module reference.

**Live site:** [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/)

Content lives under [`content/`](content/). The site is built with [Nuxt](https://nuxt.com), [Nuxt UI](https://ui.nuxt.com), and [Nuxt Content](https://content.nuxt.com). GitHub Actions deploys from `main` via [`.github/workflows/docs.yml`](../.github/workflows/docs.yml).

When cutting a NuGet release, add a note under [`content/versions/<tag>.md`](content/versions/) so it appears on the [Changelog](https://madeyoga.github.io/AuthEndpoints/changelog) page.

### Multi-package releases

This repo publishes two NuGet packages with **independent versions**:

| Package | Typical GitHub tag | Notes |
| --- | --- | --- |
| `AuthEndpoints` | `v3.0.0` | Core library |
| `AuthEndpoints.External.OAuth` | `external-oauth-v3.0.0-preview.x` | Preview OAuth module |

- Set `<Version>` only on the package(s) you intend to ship. The publish workflow packs the solution and uses `--skip-duplicate`.
- Changelog `title` should name the package + version (e.g. `AuthEndpoints.External.OAuth 3.0.0-preview.1`).
- Set frontmatter `tag` to the GitHub release tag so the changelog links correctly.
- If one GitHub release ships both packages, use body sections `### AuthEndpoints` and `### AuthEndpoints.External.OAuth`.

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
