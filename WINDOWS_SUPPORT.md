# Windows x64 support

Wild has a native COFF/PE32+ linker for
`x86_64-pc-windows-msvc`. Windows builds select link.exe-style arguments by
default. `-flavor link` selects them explicitly; `-flavor gnu` retains the ELF
driver. This is a Rust development subset, not full link.exe compatibility.

## Build and use

Prerequisites are Rust stable with the MSVC x64 target, Visual Studio C++ x64
tools, and a Windows SDK. Run from PowerShell in the repository:

```powershell
cargo +stable build --release -p wild-linker --locked
```

To use a built wild directly from a Visual Studio x64 developer shell:

```powershell
rustc +stable program.rs -C linker=C:/tools/wild.exe -C linker-flavor=msvc -C link-arg=/DEBUG:NONE
```

Or configure Cargo's target linker to the absolute path of wild.exe:

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:/tools/wild.exe"
```

Set the path to the built executable. See
[Rust development configuration](docs/windows-rust-development.md) for DLL and
PDB usage. The native linker does not delegate to another linker.

## Implemented subset

* Standard x64 COFF and bigobj inputs, archives and short import-library members.
* Lazy archive extraction, `/LIBPATH`, `LIB`, `/DEFAULTLIB`, `/NODEFAULTLIB`,
  `/WHOLEARCHIVE`, `/INCLUDE`, weak externals and `/ALTERNATENAME`.
* COMDAT selection (including associative sections), section garbage collection,
  common symbols, `$` subsection ordering, `/MERGE` and section permissions.
* Object `.drectve` processing and `/FAILIFMISMATCH` diagnostics.
* AMD64 ADDR64, ADDR32, ADDR32NB, REL32 through REL32_5, SECTION and SECREL
  relocations, with overflow and undefined-symbol errors.
* DLL imports, IATs and import thunks, image-base relocations, sorted x64
  exception tables, TLS directory and CRT initialization sections.
* Rust DLL output, function/data exports, native import libraries and PDB output
  from supported CodeView inputs. `/DEBUG:NONE` skips PDB generation.
* `/OUT`, `/ENTRY`, `/SUBSYSTEM`, `/BASE`, `/STACK`, `/HEAP`, security-header
  switches and Windows-style quoted UTF-8/UTF-16 response files.
* Deterministic executable output. `/OPT:REF` and `/OPT:NOREF` control GC;
  `/OPT:ICF` is accepted but identical-code folding is not implemented.
* `/TIME`, `/THREADS:n`, `/NO-THREADS`, `/MMAP-OUTPUT-FILE`,
  `/NO-MMAP-OUTPUT-FILE`, `/UPDATE-IN-PLACE`, `/NO-UPDATE-IN-PLACE` and
  `/UPDATE-IN-PLACE-WITH-FALLBACK` for profiling and output control.

The `libwild/src/coff/` backend supplies COFF policies and PE encoding to the
common linking engine. Input management, the sole symbol definition store
(`SymbolDb`), resolution, parallel GC, layout and address calculation use the
same engine as ELF. The PE writer consumes the resulting `Layout<Coff>`; there
is no separate COFF engine, engine-selection option or external-linker fallback.

## Limitations

General MSVC compiler-PDB/type-server/PCH support, resource and manifest
generation, incremental linking, LTCG/LLVM bitcode, CFG table generation and
architectures other than x64 are not implemented. Several existing driver
options are accepted with unsupported-option warnings or ignored compatibility
semantics; accepting an option does not promise link.exe's corresponding output.
Support does not cover every possible MSVC library convention. Legacy long-form
import objects mixed
with synthesized short imports are not part of the verified compatibility set.
Optional COFF archive members receive lightweight symbol catalogs; only selected
members materialize section bodies, relocations and directives. Candidate
discovery currently scans member symbol metadata rather than relying solely on
archive indexes, preserving index-less and incomplete-index behavior. Raw symbol
indices, including auxiliary entries, remain stable across materialization.
Byte-identical optional short imports share their first candidate in the common
input-registration path; wholearchive and normal object inputs remain distinct.
Large parsing batches and disjoint output contributions use wild's existing
Rayon pool and jobserver limits. COMDAT winners are selected in stable input
order within hash shards, and subsection sorting uses precomputed dense ranks.
Activation and diagnostics are merged deterministically. PE contributions are
copied and relocated directly in the final mapped image, honoring explicit
buffering and file replacement options. Successful Windows COFF CLI links return
jobserver tokens and finalize output, input checks and tracing before process
exit; library calls and failed links retain normal cleanup.

## Tests

```powershell
cargo +stable test -p libwild --lib coff --no-default-features --locked
```

COFF unit tests cover object layout, symbol conflicts, COMDAT selection, archive
extraction, dead-section unresolved references, directives, response-file
quoting/encoding/cycles, security headers and signed relocation addends. They
also cover indexed and incomplete archive indexes, nested associative COMDATs,
late default libraries, hash collisions, output replacement and thread-count
independent bytes and diagnostics. Windows
CI builds the workspace and runs the focused tests.

Some pre-existing all-library tests are not Windows-clean: ELF recursive
response-file parsing and Unix-path fixtures, plus tidy checks requiring taplo,
a command line exceeding Windows' length limit, and Git's materialized `ld`
symlink. These are separate from the focused COFF tests and are not changed
by this implementation.
