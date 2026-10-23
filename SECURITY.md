# Security Policy

UAPKI is a cryptographic library: it creates and verifies electronic signatures and seals, encrypts and decrypts
data and works with key storages and hardware tokens. We take security reports seriously and appreciate the work of
everyone who finds and reports a vulnerability responsibly.

## Supported Versions

| Version | Branch | Security fixes |
| ------- | ------ | -------------- |
| 3.x     | `main` | Yes            |
| 2.0.x   | `v2`   | Yes            |
| Older   | -      | No             |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull requests.**

Report them privately through GitHub: open the **Security** tab of this repository and choose
**Report a vulnerability** (GitHub private vulnerability reporting). Only the maintainers can see the report.

Please include as much of the following as you can:

- the affected version (release, branch or commit) and platform (OS, architecture, language binding);
- the kind of the issue (for example memory corruption, signature or certificate validation bypass, key or secret
  disclosure, denial of service) and its impact as you see it;
- the steps to reproduce it: the method and its parameters (JSON), the input data, the expected and the actual result;
- a proof of concept or a test case, if you have one.

Do not send real private keys, passwords or personal data. Test keys and certificates, or data from which the
personal details are removed, are enough to reproduce an issue.

## What to Expect

| Step | Time |
| ---- | ---- |
| Acknowledgement of the report | within 3 business days |
| Initial assessment (whether it is a vulnerability, its severity, the affected versions) | within 10 business days |
| Fix of a confirmed vulnerability of high or critical severity | within 30 days of the report |

We will keep you informed of the progress, may ask for more details, and will tell you when the fix is released.
Vulnerabilities of lower severity are fixed in a regular release. If a fix needs more time, we will explain why and
agree on a date with you.

## Disclosure

We follow coordinated disclosure: please give us the time above to release a fix before you publish anything about
the vulnerability. After the fix is released we publish a GitHub Security Advisory (with a CVE where applicable) and
credit the reporter, unless you prefer to stay anonymous.

## Scope

In scope:

- the libraries `uapki`, `uapkic`, `uapkif` and the storage providers (`cm-*`) in `library/`;
- the language bindings in `integration/`;
- the build scripts and the CI workflows of this repository.

Third-party components bundled with the library (for example the prebuilt libcurl in `library/common/curl`): please
report a vulnerability in such a component to its authors, and let us know as well, so that we can update the bundled
version.
