//! COFF policy and PE encoding for the shared linking pipeline.
pub(crate) mod backend;
mod exports;
mod input;
mod pdb;
mod pe_writer;
#[cfg(test)]
mod tests;
