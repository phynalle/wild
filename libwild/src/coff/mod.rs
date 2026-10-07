//! COFF policy and PE encoding for the shared linking pipeline.
pub(crate) mod backend;
mod input;
mod pe_writer;
#[cfg(test)]
mod tests;
