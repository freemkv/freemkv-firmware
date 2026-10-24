# CI and release ownership

- **dev** runs the Rust checks once for changed code. CI-only edits run workflow validation and promotion regression tests, without compiling Rust.
- **qa** owns the release test matrix, native GUI gates, package builds and install checks. The native gate compiles only the Flash GUI; shipped binaries are built by packaging.
- For a native test-probe change, run `gh workflow run qa.yml --ref dev -f native_only=true -f native_platform=windows` (or linux/macos) before promoting. This runs just that native gate, stamps no RC and creates no shipping artifacts. It cannot qualify a release.
- Stable tags download a successful QA run's complete artifacts, require matching shipping sources, verify checksums, and publish those bytes. They never invoke Cargo or rebuild packages. Missing, expired, failed or source-mismatched QA artifacts fail closed.
- Optional coverage runs manually with `gh workflow run ci.yml --ref dev -f coverage_only=true`; it does not duplicate release-candidate tests.

The debug-only native gate files and CI definitions are excluded from the shipping-source comparison. Cargo manifests, lockfiles, production Rust, assets, and packaging inputs must match. Published release assets are immutable; a failed draft upload can resume without rebuilding.
