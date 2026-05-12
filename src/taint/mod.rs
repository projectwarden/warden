//! Cross-step taint propagation.
//!
//! Many rules need to know not just "this expression reads a step output"
//! but "where did that output come from". Without that, every
//! `${{ steps.X.outputs.Y }}` read looks suspicious even when Y was
//! provably set from a safe source like `$GITHUB_REF_NAME`.
//!
//! This module walks every `run:` block in a workflow, finds writes to
//! `$GITHUB_OUTPUT`, and records a [`TaintSource`] classification per
//! `(step_id, output_key)`. Rules consult [`StepOutputProvenance`] at
//! analysis time to decide whether a finding is real, advisory, or
//! safely suppressible.

mod analyzer;
mod provenance;

pub use analyzer::build_provenance;
pub use provenance::{StepOutputProvenance, TaintSource};
