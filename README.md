# Wild: Personal Windows Development Fork

This is a fork of [Wild](https://github.com/wild-linker/wild), a linker focused on
fast iterative development. I added Windows support for my own Rust/Cargo
workflow, implementing only what I need to build and debug my projects.
The original linker is the work of the upstream Wild project and its contributors;
this is not an official upstream Windows release.

> **Personal development use only. Do not use this fork for production builds.**
> Working in my environment does not guarantee correct output or compatibility
> with yours.

## Implementation And Status

The Windows implementation and optimization work was delegated entirely to AI
through Codex, using **GPT-6.1 sol** and **GPT-6 astra**.

I do not have the linker implementation expertise to independently judge the
correctness of these changes. The practical status is: **it "just works" for my
current usage.** Tests and local validation are not an independent correctness
audit. This limitation concerns the additions in this fork, not upstream Wild.

The Windows subset targets stable Rust on `x86_64-pc-windows-msvc`, including
EXEs, DLLs, proc-macros, and PDBs for Visual Studio debugging. It is not a complete
`link.exe` replacement, and incremental linking is not implemented.

## Performance

In my own use case, measured median full-link times were lower than LLD by:

- **About 41-43%** for EXE links without PDB generation.
- **About 10-17%** for EXE links with PDB generation.

These are results from my tested workloads, not a general performance guarantee
or a reduction in total Cargo build time.

Speed takes priority over memory; the tested workloads used more memory than LLD.
Faster linking does not speed up Rust compilation or improve the whole Cargo
build by the same amount. DLL speedups are not claimed.

## Build And Use

Build this checkout with stable Rust, MSVC x64 tools, and a Windows SDK installed:

```powershell
cargo +stable build -p wild-linker --release --locked
```

The executable is `target/release/wild.exe`. To try it in a Cargo project, set
the absolute path to this binary:

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:/path/to/this/fork/target/release/wild.exe"
```

Try it in a separate configuration and keep your normal linker available.
Upstream releases do not include this fork's changes.

See [Windows support](WINDOWS_SUPPORT.md) for limitations and
[Windows Rust development](docs/windows-rust-development.md) for debugging setup.

## License

Licensed under either [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Wild by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
