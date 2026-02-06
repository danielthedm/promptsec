# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in promptsec, please report it responsibly.

**Do NOT open a public issue.**

Instead, email security concerns to the maintainers directly. You can find contact information in the repository owner's GitHub profile.

Please include:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Considerations

promptsec is a defense-in-depth library. No single guard provides complete protection against all prompt injection attacks. We recommend:

1. Using multiple guards in combination (see presets)
2. Keeping the library updated
3. Testing your specific use case with the preflight runner
4. Not relying solely on client-side filtering - always validate on the server
