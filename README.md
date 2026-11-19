# `libyaml-rust-diff-fuzz`

Differential C-to-Rust migration harness for [`yaml/libyaml`](https://github.com/yaml/libyaml)'s stateful token scanner (`src/scanner.c` / `yaml_parser_t`), designed as a deterministic verification loop for autonomous coding agent (Devin) PRs.

## Architecture

1. **Upstream Reference Oracle (`build.rs`)**
   Compiles upstream `vendor/libyaml/src/{api.c,reader.c,scanner.c}` with `-fsanitize=address -fno-omit-frame-pointer` and uses `bindgen` to expose `yaml_parser_t`, `yaml_token_t`, `yaml_parser_scan`, and `yaml_parser_fetch_more_tokens` via FFI.
2. **Structure-Aware Input Generation (`src/lib.rs`)**
   Implements `arbitrary::Arbitrary` via `StructuredYamlChunk` so `libFuzzer` / `cargo-fuzz` mutates typed YAML constructs (flow collections, block indents, anchors/aliases, directives, and raw edge-case bytes) to reach deep scanner state machine branches instead of failing on byte 0.
3. **Stateful C Isolation (`fuzz/fuzz_targets/scanner_diff.rs`)**
   Runs differential comparisons between `ffi::yaml_parser_scan` and `libyaml_rust_diff_fuzz::Scanner::scan_next_token` under `libFuzzer`'s forkserver mode (`-fork=1`) with AddressSanitizer enabled, preventing C heap/global state bleed across iterations and catching memory leaks (`yaml_token_delete` / `yaml_parser_delete`).
4. **Autonomous Agent PR Gate (`.github/workflows/fuzz-gate.yml`)**
   Every PR porting a `src/scanner.c` helper (e.g., `yaml_parser_fetch_flow_scalar`, `yaml_parser_fetch_anchor`, `yaml_parser_unroll_indent`) must survive a 60-second ASan + differential fuzz run with 0 divergences before merge.

## Running Locally

```bash
git submodule update --init --recursive
RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run scanner_diff -- -fork=1 -max_total_time=60
```
