# AuthEndpoints Documentation

Nuxt Content site for the [AuthEndpoints](https://github.com/madeyoga/AuthEndpoints) library — getting started, composable endpoints, and module reference.

**Live site:** [https://madeyoga.github.io/AuthEndpoints/](https://madeyoga.github.io/AuthEndpoints/)

Content lives under [`content/`](content/). The site is built with [Nuxt](https://nuxt.com), [Nuxt UI](https://ui.nuxt.com), and [Nuxt Content](https://content.nuxt.com). GitHub Actions deploys from `main` via [`.github/workflows/docs.yml`](../.github/workflows/docs.yml).

When cutting a NuGet release, add a note under [`content/versions/<tag>.md`](content/versions/) so it appears on the [Changelog](https://madeyoga.github.io/AuthEndpoints/changelog) page.

### Package versions

The tag prefix picks which packages a GitHub release publishes: `v*` for `AuthEndpoints`, `external-oauth-v*` for `AuthEndpoints.External.OAuth`, `AuthEndpoints.OAuth.GitHub` and `AuthEndpoints.OAuth.Google`, and `openiddict-v*` for `AuthEndpoints.OpenIddict`. See [Releases in CONTRIBUTING.md](../CONTRIBUTING.md#releases).

[![nuget](https://img.shields.io/nuget/v/AuthEndpoints?label=AuthEndpoints&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints/)
[![nuget](https://img.shields.io/nuget/v/AuthEndpoints.External.OAuth?label=External.OAuth&logo=NuGet&style=flat-square)](https://www.nuget.org/packages/AuthEndpoints.External.OAuth/)

Releases before 4.0 versioned External.OAuth on its own preview tags. Those notes stay in the changelog.

- Changelog `title` should name the package and version.
- Set frontmatter `tag` to the GitHub release tag so the changelog links correctly.
- One note per release tag. When core and add-ons ship together, each family's release gets its own note.

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
