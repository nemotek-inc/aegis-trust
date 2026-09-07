# Contributing to aegis-trust

Thanks for your interest in `aegis-trust` — the trust layer for AI agents.

> **Preview-stage project.** `aegis-trust` is a pre-GA Alpha maintained by a
> single maintainer. Issues and small, focused pull requests are welcome, but
> response times are best-effort and there is no SLA. For larger changes, please
> open an issue to discuss before investing significant effort.

## Ways to contribute

- **Report a bug** — open a [bug report](https://github.com/nemotek-inc/aegis-trust/issues/new/choose).
- **Report a security issue** — **do not** open a public issue; follow
  [`SECURITY.md`](SECURITY.md).
- **Suggest a feature** — open a feature request and describe the use case.
- **Improve docs** — doc-only PRs are especially welcome.
- **Submit a fix** — see "Pull requests" below.

## Repository layout

```
aegis-trust/
├── python/   # Python SDK   (pip install aegis-trust)
└── node/     # TypeScript / Node SDK (npm install aegis-trust)
```

The two SDKs are kept at API parity. A behavioral change in one usually needs a
matching change in the other — call out cross-SDK parity in your PR.

## Local development

**Python** (see [`python/README.md`](python/README.md) for details):

```bash
cd python
pip install -e ".[dev]"
pytest                 # test suite
mypy --strict src/aegis_trust
```

**Node / TypeScript** (see [`node/README.md`](node/README.md) for details):

```bash
cd node
npm install
npm run build          # required before tests: one suite runs the built bin-shim (dist/cli.js)
npm test               # vitest
npx tsc --noEmit       # type check (strict)
```

Please make sure the test suite and type checks pass before opening a PR.

## Pull requests

1. Fork the repo and create a topic branch from the default branch.
2. Keep the change focused — one logical change per PR.
3. Add or update tests for any behavior change.
4. If you change SDK behavior, update the relevant `CHANGELOG.md`
   (`python/CHANGELOG.md` and/or `node/CHANGELOG.md`) under an `[Unreleased]`
   section. Pre-1.0, every breaking change must be called out explicitly.
5. Keep customer-facing artifact text (README, CHANGELOG, error messages)
   English-first.
6. Fill out the pull request template.

### Commit / DCO

By submitting a pull request you certify that you wrote the contribution or
otherwise have the right to submit it under the project license, and you agree
to the [Developer Certificate of Origin](https://developercertificate.org/).
Sign your commits with `git commit -s` (adds a `Signed-off-by` trailer).

## License

`aegis-trust` is licensed under the [MIT License](LICENSE). All contributions are
accepted under the same MIT license; contributions under any other license
cannot be accepted.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By participating
you agree to uphold it.
