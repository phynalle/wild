# Windows x64 support

Wild has an initial native COFF/PE32+ executable linker for
`x86_64-pc-windows-msvc`. Windows builds select link.exe-style arguments by
default. `-flavor link` selects them explicitly; `-flavor gnu` retains the ELF
driver. This is a bootstrap-oriented subset, not full link.exe compatibility.

## Build and use

Prerequisites are Rust stable with the MSVC x64 target, Visual Studio C++ x64
tools, and a Windows SDK. Run from PowerShell in the repository:

```powershell
cargo +stable build --release -p wild-linker --locked
```

To use a built wild directly from a Visual Studio x64 developer shell:

```powershell
rustc +stable program.rs -C linker=D:\Workspace\wild\target\release\wild.exe -C linker-flavor=msvc -C link-arg=/DEBUG:NONE
```

Or configure Cargo's target linker to the absolute path of wild.exe:

```toml
[target.x86_64-pc-windows-msvc]
linker = "D:/Workspace/wild/target/release/wild.exe"
```

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
* `/OUT`, `/ENTRY`, `/SUBSYSTEM`, `/BASE`, `/STACK`, `/HEAP`, security-header
  switches and Windows-style quoted UTF-8/UTF-16 response files.
* Deterministic executable output. `/OPT:REF` and `/OPT:NOREF` control GC;
  `/OPT:ICF` is accepted but identical-code folding is not implemented.

The new `libwild/src/coff/` backend owns COFF symbol resolution and PE layout,
while sharing wild's argument infrastructure, filesystem/output abstractions,
archive reader and error reporting. It avoids treating PE semantics as ELF
semantics and leaves the existing ELF linking pipeline intact.

## Limitations

DLL/export/import-library generation, PDB/debug output, resource and manifest
generation, incremental linking, LTCG/LLVM bitcode, CFG table generation and
architectures other than x64 are not implemented. Several existing driver
options are accepted with unsupported-option warnings or ignored compatibility
semantics; accepting an option does not promise link.exe's corresponding output.
Use `/DEBUG:NONE` for the supported bootstrap configuration. No DLL output is
silently substituted for an executable: `/DLL` fails explicitly.

Support does not cover every possible MSVC library convention. Legacy long-form import objects mixed
with synthesized short imports are not part of the verified compatibility set.
The backend is currently correctness-first and serial; this work does not
establish parity with the ELF linker's performance or feature coverage.

## Tests

```powershell
cargo +stable test -p libwild --lib coff --no-default-features --locked
```

COFF unit tests cover object layout, symbol conflicts, COMDAT selection, archive
extraction, dead-section unresolved references, directives, response-file
quoting/encoding/cycles, security headers and signed relocation addends. Windows
CI builds the workspace and runs the focused tests.

Some pre-existing all-library tests are not Windows-clean: ELF recursive
response-file parsing and Unix-path fixtures, plus tidy checks requiring taplo,
a command line exceeding Windows' length limit, and Git's materialized `ld`
symlink. These are separate from the focused COFF tests and are not changed
by this implementation.
