# Building from Source

## Requirements

- macOS or Linux host
- Rust 1.77+
- LLVM/Clang
- An IDA installation, provided via `IDADIR` or discoverable from common paths
- An IDA SDK, provided via `IDASDKDIR` or `IDALIB_SDK`

`ida-cli` uses two runtime strategies:

- `idat-compat`
  Uses `idat` + IDAPython for IDA 9.0-9.2, where in-process database opening is treated as unsafe.
- `native-linked`
  Uses the vendored `idalib` backend for IDA 9.3+ runtimes.

That means the build is not restricted to one exact installed IDA runtime, but the SDK must still be present for compiling the vendored `idalib` layer.

## Clone and Build

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/path/to/ida"
export IDASDKDIR="/path/to/ida-sdk"

cargo build --bin ida-cli
```

Release build:

```bash
cargo build --release --bin ida-cli
```

## SDK Path Rules

The SDK path may point to either:

- the SDK root, for example `/path/to/ida-sdk`
- the nested `src` directory, for example `/path/to/ida-sdk/src`

The build logic accepts both layouts as long as it can find:

- `include/pro.h`
- platform libraries under `lib/...`

## Runtime Selection

At runtime, `ida-cli` probes the active IDA installation and selects a worker backend automatically.

Example:

```bash
./target/debug/ida-cli probe-runtime
```

Typical outputs:

```json
{"runtime":{"major":9,"minor":1,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

```json
{"runtime":{"major":9,"minor":3,"build":260213},"backend":"native-linked","supported":true,"reason":null}
```

## Binary Names

The primary executable is `target/debug/ida-cli` or `target/release/ida-cli`.

## Common Commands

Start the local runtime explicitly if you need the long-lived service process:

```bash
./target/debug/ida-cli serve
```

Use the flat CLI:

```bash
./target/debug/ida-cli --path /path/to/binary list-functions --limit 20
./target/debug/ida-cli --path /path/to/binary decompile --addr 0x140001000
```

Run over HTTP:

```bash
./target/debug/ida-cli serve-http --bind 127.0.0.1:8765
```

## Output Paths

- Server log: `~/.ida/logs/server.log`
- Cached databases: `~/.ida/idb/`
- CLI discovery socket: `/tmp/ida-cli.socket`
- Large response cache: `/tmp/ida-cli-out/`

## Notes

- Host support is macOS and Linux only.
- Runtime support starts at IDA 9.0.
- IDA 9.0-9.2 uses `idat-compat`; IDA 9.3+ uses `native-linked`.
- Building is native-only. Cross-compilation is not supported.
