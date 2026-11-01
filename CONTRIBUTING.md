# Contributing

Thanks for your interest!

- **Report a bug** — open an issue
- **Fix a bug** — fork, branch, PR
- **Suggest a feature** — open an issue first

## Development

```bash
cargo build
cargo test
```

Add tests for every new feature or function. Bug fixes need regression tests
that fail with the broken behavior and pass with the fix. Exercise the relevant
GUI, CLI and shared core paths when a change crosses those boundaries.

## Release notes

Write the customer-visible result: what works now, what changed, and any action
or limitation a user needs to know. Keep build machinery, CI, test counts,
refactors, dependency revisions and implementation details in commits or
internal documentation. Unreleased work stays out of stable release notes.
The website publishes reviewed notes from marketing's
`src/data/flash-changelog.md`; update that file when publishing a stable release.

## License

MIT


## Dev and QA validation

Dev runs debug Rust tests, format/lint checks, dependency checks and repository
guards. QA requires a successful dev push with an executed lint step for the
**identical Git tree**, including manifests, lockfile and CI definitions. A
skipped lint, manual coverage run or changed tree cannot supply this proof.

QA owns release-mode tests on Linux, macOS and Windows, exhaustive MediaTek
CPU contract execution, the committed OEM firmware corpus, native GUI tests
and distribution package smoke tests. The former debug CPU duplicate and QA
Linux Clippy duplicate are removed; the QA release checks remain intact.
Physical drive testing remains separate. QA-built packages continue to be
promoted at release without rebuilding. Version 0.17.0 is not released by this
CI change.
