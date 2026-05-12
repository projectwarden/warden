//! Typed workflow models.
//!
//! Replaces the untyped `serde_yaml::Value` access with `#[derive(Deserialize)]`
//! structs. Rules consume these via `LoadedWorkflow` and look up source spans
//! through the parallel `SpanTable` produced by `crate::yamlpath`.

mod common;
mod events;
mod job;
mod permissions;
mod step;
mod workflow;

pub use common::{BoolOr, Container, Credentials, Defaults, EnvValue, OneOrMany, RunDefaults};
pub use events::{EventConfig, On};
pub use job::{Concurrency, Job, NormalJob, ReusableCallJob, Strategy};
pub use permissions::{PermissionLevel, Permissions};
pub use step::{RunStep, ScalarOrExpr, Step, UsesStep};
pub use workflow::Workflow;
