pub(crate) mod alignment;
pub use args::Args;
pub(crate) mod arch;
pub(crate) mod archive;
pub mod args;
pub(crate) mod coff;
pub(crate) mod compact_unwind;
pub(crate) mod compression;
pub(crate) mod debug_trace;
pub(crate) mod diagnostics;
pub(crate) mod diff;
pub(crate) mod dwarf_address_info;
pub(crate) mod elf;
pub(crate) mod elf_aarch64;
pub(crate) mod elf_loongarch64;
pub(crate) mod elf_ppc64;
pub(crate) mod elf_riscv64;
pub(crate) mod elf_writer;
pub(crate) mod elf_x86_64;
pub(crate) mod env;
pub mod error;
pub(crate) mod export_list;
pub(crate) mod expression_eval;
pub(crate) mod file_kind;
pub(crate) mod file_writer;
pub(crate) mod fs;
pub(crate) mod gc_stats;
pub(crate) mod gdb_index;
pub(crate) mod glob_match;
pub(crate) mod grouping;
pub(crate) mod hash;
pub(crate) mod host;
pub(crate) mod input_data;
pub(crate) mod input_section_id;
pub(crate) mod layout;
pub(crate) mod layout_rules;
#[cfg_attr(not(feature = "plugins"), path = "linker_plugins_disabled.rs")]
mod linker_plugins;
pub(crate) mod linker_script;
pub(crate) mod macho;
pub(crate) mod macho_aarch64;
pub(crate) mod macho_stub_library;
pub(crate) mod macho_writer;
pub mod malfunction;
pub(crate) mod only_keep_debug;
pub(crate) mod output_kind;
pub(crate) mod output_section_id;
pub(crate) mod output_section_map;
pub(crate) mod output_section_part_map;
pub(crate) mod output_trace;
pub(crate) mod parsing;
pub(crate) mod part_id;
pub(crate) mod platform;
pub(crate) mod program_segments;
pub(crate) mod resolution;
pub(crate) mod save_dir;
pub(crate) mod sframe;
pub(crate) mod sharding;
pub(crate) mod string_merging;
pub(crate) mod subprocess;
pub(crate) mod symbol;
pub(crate) mod symbol_db;
pub(crate) mod thunks;
#[cfg(test)]
mod tidy_tests;
#[cfg(test)]
mod common_pipeline_tests {
    use object::{Object as _, ObjectSection as _};

    #[test]
    fn elf_output_uses_shared_layout_on_the_current_host() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("entry.o");
        let output = temp.path().join("image.elf");
        let mut object = object::write::Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let section = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(section, &[0xc3], 16);
        object.add_symbol(object::write::Symbol {
            name: b"_start".to_vec(),
            value: 0,
            size: 1,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(section),
            flags: object::SymbolFlags::None,
        });
        std::fs::write(&input, object.write().unwrap()).unwrap();
        let mut args = crate::args::elf::ElfArgs::default();
        args.common.output = std::sync::Arc::from(output.as_path());
        args.common.inputs.push(crate::args::Input {
            spec: crate::args::InputSpec::File(input.into()),
            modifiers: Default::default(),
            search_first: None,
        });
        let args = crate::Args::Elf(args);
        drop(crate::Linker::new().run(&args).unwrap());
        let bytes = std::fs::read(output).unwrap();
        let file = object::File::parse(&*bytes).unwrap();
        let text = file.section_by_name(".text").unwrap();
        assert_eq!(file.entry(), text.address());
        assert_eq!(text.data().unwrap()[0], 0xc3);
    }

    #[test]
    fn sparse_elf_archive_selection_is_thread_deterministic() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("inputs.a");
        let mut archive = ar::Builder::new(Vec::new());
        for index in 0..513 {
            let mut object = object::write::Object::new(
                object::BinaryFormat::Elf,
                object::Architecture::X86_64,
                object::Endianness::Little,
            );
            let section =
                object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
            object.append_section_data(section, &[if index == 512 { 0xc3 } else { 0xcc }], 16);
            object.add_symbol(object::write::Symbol {
                name: if index == 512 {
                    b"_start".to_vec()
                } else {
                    b"unused".to_vec()
                },
                value: 0,
                size: 1,
                kind: object::SymbolKind::Text,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section: object::write::SymbolSection::Section(section),
                flags: object::SymbolFlags::None,
            });
            let bytes = object.write().unwrap();
            archive
                .append(
                    &ar::Header::new(format!("{index}.o").into_bytes(), bytes.len() as u64),
                    &*bytes,
                )
                .unwrap();
        }
        std::fs::write(&input, archive.into_inner().unwrap()).unwrap();
        let mut reference = None;
        for threads in [1, 2, 4] {
            let output = temp.path().join("image.elf");
            let mut args = crate::args::elf::ElfArgs::default();
            args.common.num_threads = std::num::NonZeroUsize::new(threads);
            args.common.output = std::sync::Arc::from(output.as_path());
            args.common.inputs.push(crate::args::Input {
                spec: crate::args::InputSpec::File(input.clone().into()),
                modifiers: Default::default(),
                search_first: None,
            });
            crate::run(crate::Args::Elf(args)).unwrap();
            let bytes = std::fs::read(output).unwrap();
            let file = object::File::parse(&*bytes).unwrap();
            assert_eq!(
                file.section_by_name(".text").unwrap().data().unwrap()[0],
                0xc3
            );
            if let Some(previous) = &reference {
                assert_eq!(previous, &bytes);
            }
            reference = Some(bytes);
        }
    }
}
pub(crate) mod timing;
pub(crate) use timing::timing_guard;
pub(crate) use timing::timing_phase;
pub(crate) use timing::verbose_timing_phase;
pub(crate) mod trie;
pub(crate) mod validation;
pub(crate) mod value_flags;
pub(crate) mod verification;
pub(crate) mod version_script;
pub(crate) mod wasm;
pub(crate) mod wasm_wasm32;
pub(crate) mod wasm_writer;
pub(crate) mod writable_elf;

use crate::error::Context;
use crate::error::Result;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_kind::OutputKind;
use crate::platform::Arch;
use crate::platform::Args as _;
use crate::platform::Platform;
use crate::value_flags::PerSymbolFlags;
use crate::version_script::VersionScript;
use colosseum::sync::Arena;
use crossbeam_utils::atomic::AtomicCell;
use error::AlreadyInitialised;
pub use fs::FileReplacementMode;
pub use fs::FileSystem;
pub use fs::FileType;
pub use fs::FileWriteMode;
pub use fs::InputFileData;
pub use fs::OsFileSystem;
pub use fs::OutputFileData;
pub use fs::OutputOptions;
pub use fs::make_executable;
use hashbrown::HashSet;
use input_data::FileLoader;
use input_data::InputFile as LoadedInputFile;
use input_data::InputLinkerScript;
use layout_rules::LayoutRules;
use output_section_id::OutputSections;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::io::BufWriter;
use std::io::IsTerminal;
use std::io::Write;
use std::path::Path;
pub use subprocess::run_in_subprocess;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Runs the linker in a Rayon thread pool configured from the supplied arguments or the available
/// jobserver tokens, then cleans up associated resources. Only use this function if you've OK with
/// waiting for cleanup.
pub fn run(mut args: Args) -> error::Result {
    let _thread_guard = timing::enter_linker_thread();
    let thread_pool = args.common_mut().build_thread_pool()?;
    thread_pool.pool.install(move || -> error::Result {
        let linker = Linker::new();
        linker.run(&args)?;
        drop(linker);
        timing::finalise_perfetto_trace()?;
        Ok(())
    })?;

    Ok(())
}

/// Runs one link and terminates the process, letting the OS reclaim successful link allocations.
/// Output completion and input verification happen before returning jobserver tokens and exiting.
pub fn run_and_exit(mut args: Args) -> ! {
    let result = (|| -> error::Result {
        let thread_pool = args.common_mut().build_thread_pool()?;
        thread_pool.pool.install(|| -> error::Result {
            let linker = Linker::new();
            let output = linker.run(&args)?;
            drop(linker.shutdown_scope.take());
            drop(linker._link_scope.take());
            timing::finalise_perfetto_trace()?;
            std::io::stdout().flush()?;
            std::io::stderr().flush()?;
            std::mem::forget(output);
            std::mem::forget(linker);
            Ok(())
        })?;
        drop(thread_pool);
        Ok(())
    })();
    if let Err(error) = result {
        error::report_error_and_exit(&error);
    }
    std::process::exit(0)
}

/// Sets up whatever tracing, if any, is indicated by the supplied arguments. This can only be
/// called once and only if nothing else has already set the global tracing dispatcher. Calling this
/// is optional. If it isn't called, no tracing-based features will function. e.g. --time.
pub fn setup_tracing(args: &Args) -> Result<(), AlreadyInitialised> {
    if let Some(opts) = args.common().time_phase_options.as_ref() {
        timing::init_tracing(opts)
    } else if args.common().print_allocations.is_some() {
        debug_trace::init()
    } else {
        tracing_subscriber::registry()
            .with(fmt::layer().with_ansi(std::io::stdout().is_terminal()))
            .with(EnvFilter::from_env("WILD_LOG"))
            .try_init()
            .map_err(|_| AlreadyInitialised)
    }
}

/// This is effectively a data store for use while linking. It takes ownership of all the input data
/// that we read, which allows the linking stages to borrow that data. Dropping this struct might be
/// expensive, so the caller of the linker might want to think about when best to drop it - probably
/// together with the `LinkerOutput`. Note, calling `exit` without dropping this struct is an
/// option, but likely won't save any time, since the bulk of the work done during drop (unmapping
/// pages) will still happen anyway.
pub struct Linker<F: FileSystem = OsFileSystem> {
    /// We store our input files here once we've read them.
    inputs_arena: Arena<input_data::InputFile<F::Input>>,

    linker_plugin_arena: Arena<linker_plugins::LoadedPlugin>,

    /// Anything that doesn't need a custom Drop implementation can go in here. In practice, it's
    /// mostly just the decompressed copy of compressed string-merge sections.
    herd: bumpalo_herd::Herd,

    /// We'll fill this in when we're done linking and start shutting down. Once this is dropped,
    /// that signals the end of shutdown for the purposes of timing measurement.
    #[allow(dyn_drop)]
    shutdown_scope: AtomicCell<Vec<Box<dyn Drop>>>,

    /// A timing scope that exists for the whole time we're linking.
    #[allow(dyn_drop)]
    _link_scope: AtomicCell<Vec<Box<dyn Drop>>>,

    // File system used for reading of the inputs and writing of the output file(s).
    file_system: std::sync::Arc<F>,
}

pub struct LinkerOutput<'layout_inputs> {
    #[allow(dyn_drop)]
    /// This is just here so that we defer its destruction. This allows us to (a) measure how long
    /// it takes to drop and (b) if we forked, signal our parent that we're done, then drop it in
    /// the background.
    layout: Option<Box<dyn Drop + Send + 'layout_inputs>>,

    /// Input mmaps, released in parallel on drop so later unmap is cheap.
    input_file_data: Vec<&'layout_inputs dyn InputFileData>,
}

impl Linker<OsFileSystem> {
    #[must_use]
    pub fn new() -> Self {
        Self::with_file_system(OsFileSystem::new())
    }
}

impl<F: FileSystem> Linker<F> {
    pub fn with_file_system(file_system: F) -> Self {
        let thread_guard = timing::enter_linker_thread();
        let (guard_a, guard_b) = timing_guard!("Link");

        Self {
            file_system: std::sync::Arc::new(file_system),
            inputs_arena: Arena::new(),
            linker_plugin_arena: Arena::new(),
            herd: Default::default(),
            shutdown_scope: Default::default(),
            _link_scope: AtomicCell::new(vec![
                Box::new(guard_a),
                Box::new(guard_b),
                Box::new(thread_guard),
            ]),
        }
    }

    /// Runs the linker. The returned value isn't useful for anything, but is somewhat expensive to
    /// drop, so we leave it up to the caller to decide when to drop it. At the point at which we
    /// return, the output file should be usable.
    ///
    /// This method runs in whatever Rayon thread pool is currently installed. If no thread pool is
    /// installed, then Rayon's default global thread pool will be created and used. In either case,
    /// the value of `--threads` in `args` has no effect. If you want a thread pool configured from
    /// the supplied arguments, use the top-level [`run`] function instead, which creates such a
    /// pool, runs the linker in it, then tears it down together with other associated resources.
    pub fn run<'layout_inputs>(
        &'layout_inputs self,
        args: &'layout_inputs Args,
    ) -> error::Result<LinkerOutput<'layout_inputs>> {
        let identity = args.common().linker_identity();
        match args.common().version_mode {
            args::VersionMode::ExitAfterPrint => {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{identity}")?;
                return Ok(LinkerOutput::empty());
            }
            args::VersionMode::Verbose => {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{identity}")?;
                // Continue linking if object files are specified
                if args.common().inputs.is_empty() {
                    return Ok(LinkerOutput::empty());
                }
            }
            args::VersionMode::VerboseWithEmulations => {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{identity}")?;
                args.print_emulation_info(&mut stdout)?;
                // Continue linking if object files are specified
                if args.common().inputs.is_empty() {
                    return Ok(LinkerOutput::empty());
                }
            }
            args::VersionMode::None => {
                // Don't print version
            }
        }

        match args {
            Args::Coff(args) => {
                crate::ensure!(!args.is_dll, "COFF DLL output is not supported yet");
                self.link_for_arch::<coff::backend::Coff, coff::backend::CoffX64>(args)
            }
            Args::Elf(elf_args) => crate::elf::link_for_arch(self, elf_args),
            Args::MachO(macho_args) => crate::macho::link_for_arch(self, macho_args),
            Args::Wasm(wasm_args) => crate::wasm::link_for_arch(self, wasm_args),
        }
    }

    fn link_for_arch<'data, P: Platform, A: Arch<Platform = P>>(
        &'data self,
        args: &'data P::Args,
    ) -> error::Result<LinkerOutput<'data>> {
        let mut file_loader = input_data::FileLoader::new(
            &self.inputs_arena,
            std::sync::Arc::clone(&self.file_system),
        );

        // Note, we propagate errors from `link_with_input_data` after we've checked if any files
        // changed. We want inputs-changed errors to take precedence over all other errors.
        let result = self.load_inputs_and_link::<P, A>(&mut file_loader, args);

        file_loader.verify_inputs_unchanged()?;

        // Write the dependency file and inputs trace after successful linking.
        if result.is_ok() {
            if let Some(dep_file_path) = &args.dependency_file() {
                write_dependency_file(
                    self.file_system.as_ref(),
                    dep_file_path,
                    args.output(),
                    &file_loader.loaded_files,
                )
                .with_context(|| {
                    format!(
                        "Failed to write dependency file `{}`",
                        dep_file_path.display()
                    )
                })?;
            }
            if args.should_write_trace_file() {
                let mut buf = BufWriter::new(std::io::stdout());
                for input in &file_loader.loaded_files {
                    writeln!(buf, "{}", input.filename.display())?;
                }
            }
        }

        result
    }

    pub fn file_system(&self) -> &F {
        self.file_system.as_ref()
    }

    fn load_inputs_and_link<'data, P: Platform, A: Arch<Platform = P>>(
        &'data self,
        file_loader: &mut FileLoader<'data, F>,
        args: &'data P::Args,
    ) -> error::Result<LinkerOutput<'data>> {
        let mut plugin = P::maybe_init_linker_plugin(args, &self.linker_plugin_arena, &self.herd)?;

        let loaded = file_loader.load_inputs::<P>(&args.common().inputs, args, &mut plugin);

        args.common().save_dir.finish(file_loader, args)?;

        let loaded = loaded?;

        let output_kind = OutputKind::new(args, file_loader);

        let mut output = file_writer::Output::new::<P>(args, output_kind, self.file_system.clone());

        let mut output_sections = OutputSections::with_base_address(
            args.image_base()
                .unwrap_or_else(|| A::start_memory_address(output_kind)),
            output_kind,
        );
        if let Some(base) = args.image_base() {
            let page_size = args.loadable_segment_alignment().value();
            if base % page_size != 0 {
                bail!("--image-base: address isn't multiple of page size: {base:#x}");
            }
        }
        output_sections.set_rosegment(args.rosegment());

        let mut layout_rules_builder = LayoutRulesBuilder::default();

        let auxiliary =
            input_data::AuxiliaryFiles::new(args, &self.inputs_arena, self.file_system.as_ref())?;

        let mut symbol_db = symbol_db::SymbolDb::new(args, output_kind, &auxiliary, &self.herd)?;
        let mut per_symbol_flags = PerSymbolFlags::new();

        symbol_db.add_inputs(
            &mut per_symbol_flags,
            &mut output_sections,
            &mut layout_rules_builder,
            loaded,
        )?;

        symbol_db.apply_wrapped_symbol_overrides();

        let mut resolver = resolution::Resolver::default();

        let mut input_resolution_state = P::InputResolutionState::default();
        loop {
            resolver.resolve_symbols_and_select_archive_entries(
                &mut symbol_db,
                &mut per_symbol_flags,
            )?;
            let expand_inputs = timing_guard!("Expand selected inputs");
            let changed = P::resolve_input_extensions(
                &mut input_resolution_state,
                &mut symbol_db,
                &mut resolver,
                file_loader,
                &mut per_symbol_flags,
                &mut output_sections,
                &mut layout_rules_builder,
            )?;
            drop(expand_inputs);
            if !changed {
                break;
            }
        }
        {
            timing_phase!("Select input sections");
            P::select_input_sections(&mut symbol_db, &resolver.resolved_groups)?;
        }
        let configure_layout = timing_guard!("Configure input layout");
        P::configure_input_layout(
            &input_resolution_state,
            &symbol_db,
            &resolver.resolved_groups,
            &mut output_sections,
            &mut layout_rules_builder,
        )?;
        drop(configure_layout);

        // Now that we know which archive entries are being loaded, we can resolve alternative
        // symbol definitions.
        crate::symbol_db::resolve_alternative_symbol_definitions(
            &mut symbol_db,
            &mut per_symbol_flags,
            &resolver.resolved_groups,
        )?;
        {
            timing_phase!("Finalise symbol definitions");
            P::finalise_input_definitions(&mut symbol_db, &resolver.resolved_groups)?;
        }

        if let Some(plugin) = plugin.as_mut()
            && plugin.is_initialised()
        {
            P::plugin_all_symbols_read(
                plugin,
                &mut symbol_db,
                &mut resolver,
                file_loader,
                &mut per_symbol_flags,
                &mut output_sections,
                &mut layout_rules_builder,
            )?;
        }

        // If it's a rust version script, apply the global symbol visibility now.
        // We previously downgraded all symbols to local visibility.
        if let VersionScript::Rust(rust_vscript) = &symbol_db.version_script {
            symbol_db.handle_rust_version_script(rust_vscript, &mut per_symbol_flags);
        }

        let layout_rules = layout_rules_builder.build::<P>(args);

        let resolved = resolver.resolve_sections_and_canonicalise_undefined(
            &mut symbol_db,
            &mut per_symbol_flags,
            &mut output_sections,
            &layout_rules,
        )?;

        let layout = layout::compute::<P, A, F>(
            symbol_db,
            per_symbol_flags,
            resolved,
            output_sections,
            &mut output,
        )?;

        P::write_output_file::<A, F>(&output, &layout)?;
        diff::maybe_diff()?;

        // We've finished linking. We consider everything from this point onwards as shutdown.
        let (g1, g2) = timing_guard!("Shutdown");
        self.shutdown_scope.store(vec![Box::new(g1), Box::new(g2)]);

        let input_file_data = file_loader
            .loaded_files
            .iter()
            .filter_map(|file| Some(file.storage()? as &dyn InputFileData))
            .collect();

        Ok(LinkerOutput {
            layout: Some(Box::new(layout)),
            input_file_data,
        })
    }
}

impl Default for Linker<OsFileSystem> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FileSystem> Drop for Linker<F> {
    fn drop(&mut self) {
        timing_phase!("Drop inputs");
        self.inputs_arena = Arena::new();
        self.herd = Default::default();
    }
}

impl Drop for LinkerOutput<'_> {
    fn drop(&mut self) {
        timing_phase!("Drop layout");

        let input_file_data = std::mem::take(&mut self.input_file_data);

        rayon::join(
            || {
                input_file_data
                    .par_iter()
                    .for_each(|file| file.release_memory());
            },
            || {
                self.layout.take();
            },
        );
    }
}

impl LinkerOutput<'_> {
    fn empty() -> Self {
        LinkerOutput {
            layout: None,
            input_file_data: Vec::new(),
        }
    }
}

/// Writes a dependency file in Makefile format.
fn write_dependency_file<I: InputFileData>(
    file_system: &impl FileSystem,
    dep_file_path: &Path,
    output_path: &Path,
    loaded_files: &[&LoadedInputFile<I>],
) -> Result<()> {
    timing_phase!("Write dependency file");

    let mut writer = Vec::new();

    // Collect unique dependency paths
    let mut seen = HashSet::new();
    let mut deps = Vec::new();
    for input_file in loaded_files {
        // Skip temporary files. e.g. those generated by linker plugins.
        if input_file.modifiers.temporary {
            continue;
        }

        let path_str = input_file.filename.display().to_string();
        if seen.insert(path_str.clone()) {
            deps.push(path_str);
        }
    }

    write!(writer, "{}:", output_path.display())?;

    for dep in &deps {
        write!(writer, " {dep}")?;
    }

    writeln!(writer)?;

    for dep in &deps {
        writeln!(writer, "\n{dep}:")?;
    }

    file_system.write_auxiliary(dep_file_path, &writer)?;
    Ok(())
}

/// Possibly initialise timing if a timing-related environment variable is active and it was enabled
/// in the build, otherwise, do nothing. See `BENCHMARKING.md` for details.
pub fn init_timing() -> Result {
    timing::setup()
}

pub fn should_fork(args: &Args) -> bool {
    cfg!(feature = "fork") && crate::host::process::CAN_FORK && args.common().should_fork()
}
