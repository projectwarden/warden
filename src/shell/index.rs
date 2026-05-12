//! `ShellIndex`: per-step parsed bash scripts indexed by step path.
//!
//! Built lazily during V2 audit so workflows without any V2 rules touching
//! shell pay nothing.

use crate::models::{Job, Step, Workflow};

#[cfg(feature = "shell-analysis")]
use super::queries::{find_special_file_writes, SpecialFileWrite};

/// One parsed `run:` block.
#[derive(Debug, Clone)]
pub struct ShellOccurrence {
    /// Logical YAML path: `jobs.<name>.steps[<i>].run`.
    pub path: String,
    /// Verbatim script text.
    pub script: String,
    /// Detected writes to GitHub special files (env/path/output).
    #[cfg(feature = "shell-analysis")]
    pub special_writes: Vec<SpecialFileWrite>,
}

#[derive(Debug, Default)]
pub struct ShellIndex {
    occurrences: Vec<ShellOccurrence>,
}

impl ShellIndex {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn build(workflow: &Workflow) -> Self {
        #[cfg(not(feature = "shell-analysis"))]
        {
            // Shell analysis disabled: collect script text only, no parsing.
            let mut occurrences = Vec::new();
            for (job_name, job) in &workflow.jobs {
                if let Job::Normal(j) = job {
                    for (i, step) in j.steps.iter().enumerate() {
                        if let Step::Run(r) = step {
                            occurrences.push(ShellOccurrence {
                                path: format!("jobs.{job_name}.steps[{i}].run"),
                                script: r.run.clone(),
                            });
                        }
                    }
                }
            }
            return Self { occurrences };
        }

        #[cfg(feature = "shell-analysis")]
        {
            let mut occurrences = Vec::new();
            for (job_name, job) in &workflow.jobs {
                if let Job::Normal(j) = job {
                    for (i, step) in j.steps.iter().enumerate() {
                        if let Step::Run(r) = step {
                            // Skip non-bash shells. PowerShell support deferred.
                            let shell_kind = r.shell.as_deref().unwrap_or("bash");
                            if !matches!(shell_kind, "bash" | "sh" | "/bin/bash" | "/bin/sh") {
                                occurrences.push(ShellOccurrence {
                                    path: format!("jobs.{job_name}.steps[{i}].run"),
                                    script: r.run.clone(),
                                    special_writes: Vec::new(),
                                });
                                continue;
                            }
                            let writes = match super::parser::parse_bash(&r.run) {
                                Some(tree) => find_special_file_writes(tree.root_node(), &r.run),
                                None => Vec::new(),
                            };
                            occurrences.push(ShellOccurrence {
                                path: format!("jobs.{job_name}.steps[{i}].run"),
                                script: r.run.clone(),
                                special_writes: writes,
                            });
                        }
                    }
                }
            }
            Self { occurrences }
        }
    }

    pub fn occurrences(&self) -> &[ShellOccurrence] {
        &self.occurrences
    }

    pub fn is_empty(&self) -> bool {
        self.occurrences.is_empty()
    }

    pub fn len(&self) -> usize {
        self.occurrences.len()
    }
}
