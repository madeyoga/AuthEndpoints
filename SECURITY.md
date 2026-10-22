# Security policy

## Supported versions

4.x is the current line and receives all fixes (features, bugs, and security).

Fixes land in the latest 4.x patch only. Stay on the newest 4.x.

If 5.0 ships, 4.x continues to receive security fixes for 12 months after the 5.0 release.

3.x and older are unsupported. Upgrade to 4.x.

| Version | Supported |
| --- | --- |
| 4.x | Yes |
| < 4.0 | No |

## Reporting a vulnerability

Report privately via [GitHub private vulnerability reporting](https://github.com/madeyoga/AuthEndpoints/security/advisories/new) (Security tab > Report a vulnerability). That is the preferred route. If you can't use it, email [security@harten.id](mailto:security@harten.id). Never open a public issue.

Include the affected version, steps to reproduce, and the expected impact.

## What happens next

- We acknowledge the report within 3 working days.
- High and critical issues are fixed as soon as possible.
- The fix ships as a NuGet release, together with a GitHub security advisory and a CVE.
- Reporters are credited in the advisory if they want.

## Out of scope

- Misconfiguration in the consuming app (weak cookie settings, a missing HTTPS redirect, and similar), unless it is caused by the library's defaults.
- Vulnerabilities in dependencies such as ASP.NET Core Identity. Report those to their maintainers.
