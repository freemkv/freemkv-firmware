# Firmware fuzzing

This standalone cargo-fuzz workspace performs no device I/O. Seed `corpus/firmware/`
with the private OEM corpus used by the firmware-fact tests; do not commit firmware.
The input limit bounds allocation and analysis cost. Reproducers belong in regression
unit tests after minimization and review; a fuzz run supplements the OEM known answers.

```sh
cargo +nightly fuzz run firmware -- -max_total_time=300 -timeout=10 -rss_limit_mb=4096
```

Record the source commit, toolchain, seed hashes, elapsed time, executions and any
artifacts with each run. Separate workers use independent artifact directories.
