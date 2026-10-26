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

## Security

Never report a vulnerability in a public issue. Follow [SECURITY.md](SECURITY.md).

## Questions and bugs

- Questions and ideas: [Discussions](https://github.com/madeyoga/AuthEndpoints/discussions)
- Bugs and feature requests: [Issues](https://github.com/madeyoga/AuthEndpoints/issues/new/choose)

By taking part, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
