# Rust development on Windows x64

The COFF backend supports Rust EXEs, `dylib`, `cdylib`, and proc-macro DLLs,
with native PDB generation. DLL exports, debug-directory records, and their
synthetic sections participate in the common input/resolution/GC/Layout path.
PE, PDB, and import-library writers consume that final layout; no external
linker is used to produce these outputs.

## Cargo configuration

Build the linker with stable Rust:

```powershell
cargo +stable build -p wild-linker --release --locked
```

Use an absolute linker path in a separate Cargo configuration file while
validating a project:

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:/tools/wild.exe"

[profile.dev]
debug = 2
opt-level = 0
```

Apply this file with `cargo +stable --config <configuration-file> build` and
a separate `--target-dir`. Preserve the project's dependency optimization
settings. To make wild the project's default after validation, put the target
linker setting in its `.cargo/config.toml`. Rust supplies the export definition,
PDB options, and standard-library NATVIS files itself.

The Windows SDK and MSVC CRT libraries remain required. Existing DLL imports
are supported; producing a PDB does not require the DIA SDK or Visual Studio.
Those tools are used only for validation and debugging.

## Visual Studio

Open the generated EXE as a project, with its matching PDB and DLLs available.
Add the directories containing the application's DLLs and the Rust sysroot's
`lib/rustlib/x86_64-pc-windows-msvc/lib` directory to the debugging environment's
`PATH`. Set the working directory so application resources can be located.

Set source breakpoints in the game and DLL. Rust's NATVIS records are embedded
in the PDB, including their original contents. Dependencies compiled with
optimization can still have optimized-away variables or inlined frames;
use `debug = 2` and `opt-level = 0` for code being debugged.

## Options and outputs

- `/DLL`, `/DEF`, `/EXPORT`, `/IMPLIB`, `/NOENTRY`, and `/ENTRY` select DLL
  behavior. The default DLL entry is `_DllMainCRTStartup`.
- `/DEBUG`, `/DEBUG:FULL`, `/DEBUG:NONE`, `/PDB`, `/PDBALTPATH`, and `/NATVIS`
  control debug output. `/DEBUG:NONE` does not merge CodeView or create a PDB.
- Explicit `/OPT:REF` or `/OPT:NOREF` takes precedence over debug defaults,
  independently of option order.
- PE, PDB, and import-library output paths must be distinct. Failures writing
  any required output fail the link. The shared output writer handles mapping,
  buffered writes, replacement, flush, and file lifetime.
- Threads and output-write modes use the existing common engine controls.
  All links are full links, not incremental links.

## Supported scope

Support is scoped to Windows x64 COFF/CodeView emitted by the tested stable
Rust toolchain and supported dependencies. Unsupported debug records
are diagnosed, not silently discarded. Debug references do not keep dead code
alive, and unselected archive members do not contribute debug records.

General MSVC compiler-PDB/type-server/PCH support, advanced inline debugging,
export forwarders, source-server records, FASTLINK, Edit and Continue,
incremental linking, input LTO, ICF, and new CFG implementation are outside
this development subset. This is not a claim of complete `link.exe` or PDB
format compatibility.
