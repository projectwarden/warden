//! Shell parsing for `run:` blocks via tree-sitter-bash.
//!
//! Gated behind the default-on `shell-analysis` cargo feature. With the
//! feature off, [`ShellIndex::build`] returns an empty index and helpers
//! produce no findings, so rules degrade to "shell-blind" behavior rather
//! than failing to compile.

mod index;
#[cfg(feature = "shell-analysis")]
mod parser;
#[cfg(feature = "shell-analysis")]
mod queries;

pub use index::{ShellIndex, ShellOccurrence};

#[cfg(feature = "shell-analysis")]
pub use queries::{GithubSpecialFile, SpecialFileWrite};

#[cfg(not(feature = "shell-analysis"))]
pub use stub::{GithubSpecialFile, SpecialFileWrite};

#[cfg(not(feature = "shell-analysis"))]
mod stub {
    /// Stub when `shell-analysis` is disabled; never constructed.
    #[derive(Debug, Clone, Copy)]
    pub enum GithubSpecialFile {
        Env,
        Path,
        Output,
    }
    #[derive(Debug, Clone)]
    pub struct SpecialFileWrite {
        pub file: GithubSpecialFile,
        pub byte_start_in_script: usize,
        pub byte_end_in_script: usize,
    }
}
