# Fuzzing

Five libFuzzer targets cover arbitrary self-describing, compact and CBOR input,
structured roundtrips, and entropy/projection frames. Frame tests also mutate
valid encodings so format headers do not prevent exploration of their parsers.
Each target uses finite input and collection policies. These campaigns do not
measure peak heap usage or certify custom trait implementations.

Install the tools from the repository root:

```text
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked --root target/fuzz-tools
```

Run in PowerShell (PowerShell 7 also works on Linux):

```powershell
./scripts/fuzz.ps1 -Seconds 120
./scripts/fuzz.ps1 -Targets decode_compact_arbitrary -Seconds 600 -Seed 102
```

On Windows, install Visual Studio C++ Build Tools and its C++ AddressSanitizer
component. The runner finds the ASan runtime through `vswhere` and adds its
directory to the process PATH. It restores PATH when finished. Use `cargo
+nightly fuzz run`, not ordinary `cargo run`; the latter does not configure
the libFuzzer entry point and instrumentation. See the
[official Windows setup](https://rust-fuzz.github.io/book/cargo-fuzz/windows/setup.html).

The runner stores tool versions, seed, limits, exit status and execution counts
under `target/fuzz-results/<timestamp>/report.json`, alongside full logs. It
fails if a target fails or produces no completion summary. Corpus files persist
under `fuzz/corpus`; a seed alone does not reproduce a campaign with a different
corpus or compiler. libFuzzer writes failure inputs under `fuzz/artifacts` when
its platform crash handler can capture them; an abort may leave only the log.
Reproduce a captured input with:

```text
cargo +nightly fuzz run TARGET fuzz/artifacts/TARGET/INPUT
```

CI runs a 30-second smoke campaign per target on Windows and Linux and uploads
logs and captured failures. Longer campaigns remain a separate validation task.
