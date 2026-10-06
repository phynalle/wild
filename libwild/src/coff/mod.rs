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
use crate::fs::OutputFileData;
use crate::fs::OutputOptions;

pub(crate) fn link<F: FileSystem>(fs: &F, args: &CoffArgs) -> Result {
    crate::ensure!(!args.is_dll, "COFF DLL output is not supported yet");
    let mut linker = resolve::Resolver::new(fs, args);
    linker.load()?;
    linker.resolve()?;
    let bytes = writer::write(&mut linker)?;
    let mut output = fs.create_output(
        args.common.output.clone(),
        OutputOptions {
            size: bytes.len() as u64,
            file_replacement_mode: args
                .common
                .file_replacement_mode
                .unwrap_or(FileReplacementMode::UnlinkAndReplace),
            write_mode: args.common.file_write_mode,
            fallocate: Some(false),
            madvise_huge_pages: Some(false),
        },
    )?;
    output.bytes_mut().copy_from_slice(&bytes);
    output.finish()
}
