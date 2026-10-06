//! Native x64 COFF linking. COFF's archive directives and section selection are
//! resolved together before PE layout; host I/O remains shared with other formats.
mod input;
mod resolve;
#[cfg(test)]
mod tests;
mod writer;

use crate::args::coff::CoffArgs;
use crate::error::Result;
use crate::fs::FileReplacementMode;
use crate::fs::FileSystem;
use crate::fs::FileWriteMode;
use crate::fs::OutputOptions;

pub(crate) fn link<F: FileSystem>(fs: &F, args: &CoffArgs) -> Result {
    crate::ensure!(!args.is_dll, "COFF DLL output is not supported yet");
    let _thread = crate::timing::enter_linker_thread();
    crate::timing_phase!("COFF link");
    let mut linker = resolve::Resolver::new(fs, args);
    {
        crate::timing_phase!("COFF load");
        linker.load()?;
    }
    {
        crate::timing_phase!("COFF resolve");
        linker.resolve()?;
    }
    linker.report_work_timing();
    let bytes = {
        crate::timing_phase!("COFF write");
        writer::write(&mut linker)?
    };
    let _output_time = crate::timing_guard!("COFF output");
    fs.write_output(
        args.common.output.clone(),
        OutputOptions {
            size: bytes.len() as u64,
            file_replacement_mode: args
                .common
                .file_replacement_mode
                .unwrap_or(FileReplacementMode::UnlinkAndReplace),
            write_mode: Some(
                args.common
                    .file_write_mode
                    .unwrap_or(FileWriteMode::BufferThenWrite),
            ),
            fallocate: Some(false),
            madvise_huge_pages: Some(false),
        },
        &bytes,
    )?;
    drop(_output_time);
    crate::timing_phase!("COFF release inputs");
    drop(linker);
    drop(bytes);
    Ok(())
}
