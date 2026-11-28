#!/usr/bin/env bash
# Prints the projects that a release tag publishes, one path per line, relative to the repo root.
# Fails, before anything is packed or pushed, when:
#   - the tag prefix is not one of the families below;
#   - the tag's version is not a SemVer 2.0 version (no build metadata);
#   - a selected project's <Version> differs from the tag's version;
#   - the release's pre-release flag differs from the version (a suffix such as -preview.1 must be a pre-release).
#
# Usage: release-packages.sh <tag> <prerelease: true|false>
# Used by .github/workflows/publish-to-nuget.yml. Tested by ReleasePackagesScriptTests.
set -euo pipefail

fail() {
  echo "::error::$1" >&2
  exit 1
}

[ "$#" -eq 2 ] || fail "usage: release-packages.sh <tag> <prerelease: true|false>"
tag="$1"
prerelease="$2"

# Tag prefix -> projects. A new package goes in the family it ships with.
case "$tag" in
  external-oauth-v*)
    version="${tag#external-oauth-v}"
    projects=(
      src/AuthEndpoints.External.OAuth/AuthEndpoints.External.OAuth.csproj
      src/AuthEndpoints.OAuth.GitHub/AuthEndpoints.OAuth.GitHub.csproj
      src/AuthEndpoints.OAuth.Google/AuthEndpoints.OAuth.Google.csproj
    )
    ;;
  openiddict-v*)
    version="${tag#openiddict-v}"
    projects=(
      src/AuthEndpoints.OpenIddict/AuthEndpoints.OpenIddict.csproj
    )
    ;;
  v[0-9]*)
    version="${tag#v}"
    projects=(
      src/AuthEndpoints/AuthEndpoints.csproj
      src/AuthEndpoints.EntityFrameworkCore/AuthEndpoints.EntityFrameworkCore.csproj
    )
    ;;
  *)
    fail "Tag '$tag' has no known prefix. Use v<version> (AuthEndpoints, EntityFrameworkCore), external-oauth-v<version> (External.OAuth, OAuth.GitHub, OAuth.Google) or openiddict-v<version> (OpenIddict)."
    ;;
esac

semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
[[ "$version" =~ $semver ]] || fail "Tag '$tag' does not end in a version such as 5.0.0 or 5.0.0-preview.1: '$version'."

case "$prerelease" in
  true)
    [[ "$version" == *-* ]] || fail "Release '$tag' is marked pre-release, but $version has no pre-release suffix. Clear the pre-release flag, or tag a suffixed version."
    ;;
  false)
    [[ "$version" != *-* ]] || fail "Release '$tag' is not marked pre-release, but $version has a pre-release suffix. Mark the release as pre-release."
    ;;
  *)
    fail "The pre-release flag must be true or false, got '$prerelease'."
    ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mismatch=0
for project in "${projects[@]}"; do
  [ -f "$root/$project" ] || fail "Project $project is missing. Update the tag map in .github/scripts/release-packages.sh."
  actual="$(dotnet msbuild "$root/$project" -nologo -getProperty:Version | tr -d '[:space:]')"
  if [ "$actual" != "$version" ]; then
    echo "::error::$project has <Version>$actual</Version>, but tag '$tag' is $version." >&2
    mismatch=1
  fi
done
[ "$mismatch" -eq 0 ] || exit 1

printf '%s\n' "${projects[@]}"
