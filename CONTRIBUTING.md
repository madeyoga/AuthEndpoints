# Contributing to AuthEndpoints

Thanks for helping. This guide covers what you need to send a change.

## Build and test

You need the .NET 10 SDK (the libraries target `net10.0`).

```bash
dotnet restore AuthEndpoints.sln
dotnet build AuthEndpoints.sln
dotnet test AuthEndpoints.sln
```

`dotnet test` runs every test project. CI runs the same commands on each pull request.

## Run it locally

- The [quick start](https://authendpoints.harten.id/getting-started/quick-start/) builds a minimal app in a few minutes.
- `tests/AuthEndpoints.Tests` is also a runnable demo host: `dotnet run --project tests/AuthEndpoints.Tests`.

## Pull requests

- One change per pull request. Keep it focused.
- Add or update tests for any behavior change. PRs without tests for new behavior will not be merged.
- Update the docs under `Documentation/content` when you change public behavior.
- Make sure `dotnet build` and `dotnet test` pass before you open the PR.
- For a larger change, open an issue first so we can agree on the approach.

## Dependency versions

The package versions in `src/` are the minimums every consumer must have. We raise them only when a security advisory or a required API needs it, so please don't send PRs that only bump library dependencies. Test projects can track the latest versions.

## Releases

Maintainers publish to NuGet by publishing a GitHub release. The tag prefix picks the packages:

| Tag | Packages |
| --- | --- |
| `v<version>` | `AuthEndpoints`, `AuthEndpoints.EntityFrameworkCore` |
| `external-oauth-v<version>` | `AuthEndpoints.External.OAuth`, `AuthEndpoints.OAuth.GitHub`, `AuthEndpoints.OAuth.Google` |
| `openiddict-v<version>` | `AuthEndpoints.OpenIddict`, `AuthEndpoints.OpenIddict.EntityFrameworkCore` |

- Set `<Version>` in each of those projects to the tag's version before you tag. The add-on packages in one family share a version.
- Mark the GitHub release as a pre-release exactly when the version has a suffix, such as `5.0.0-preview.1`.
- To ship core and add-ons together, publish one release per family, core first.

[`.github/scripts/release-packages.sh`](.github/scripts/release-packages.sh) checks the tag, before anything is built or pushed. The publish fails on an unknown prefix, a version that doesn't match `<Version>`, or a pre-release flag that doesn't match the version. It also fails when every selected package is already on NuGet.

Each add-on depends on `AuthEndpoints` from the core version in `src/AuthEndpoints` up to the next major, for example `[5.0.0, 6.0.0)`. [`src/AuthEndpoints.DependencyRange.targets`](src/AuthEndpoints.DependencyRange.targets) sets this at pack time. Pack an add-on from a commit whose core version the add-on supports as its minimum. `AuthEndpoints.OpenIddict.EntityFrameworkCore` depends on `AuthEndpoints.OpenIddict` the same way, through `AuthEndpointsRangedProjects`.

## Security

Never report a vulnerability in a public issue. Follow [SECURITY.md](SECURITY.md).

## Questions and bugs

- Questions and ideas: [Discussions](https://github.com/madeyoga/AuthEndpoints/discussions)
- Bugs and feature requests: [Issues](https://github.com/madeyoga/AuthEndpoints/issues/new/choose)

By taking part, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
