//! Unit tests for `warden upstream` parsing and resolver helpers.
//! All tests are hermetic: no network, no disk beyond a tmpdir.

use std::fs;

use wardenscan::audit::{cargo, manifest, npm, pypi};

#[test]
fn test_npm_resolver_parses_repository_url() {
    let body = serde_json::json!({
        "name": "lodash",
        "repository": {
            "type": "git",
            "url": "git+https://github.com/lodash/lodash.git"
        }
    });
    let url = npm::extract_repository_url(&body).unwrap();
    let (owner, repo) = manifest::normalize_github_url(&url).unwrap();
    assert_eq!(owner, "lodash");
    assert_eq!(repo, "lodash");
}

#[test]
fn test_npm_resolver_string_repository() {
    let body = serde_json::json!({
        "name": "x",
        "repository": "https://github.com/foo/bar"
    });
    let url = npm::extract_repository_url(&body).unwrap();
    let (owner, repo) = manifest::normalize_github_url(&url).unwrap();
    assert_eq!(owner, "foo");
    assert_eq!(repo, "bar");
}

#[test]
fn test_pypi_resolver_falls_back_to_homepage() {
    // No project_urls.Source, only Homepage points at github
    let body = serde_json::json!({
        "info": {
            "home_page": "",
            "project_urls": {
                "Documentation": "https://example.com/docs",
                "Homepage": "https://github.com/psf/requests"
            }
        }
    });
    let cand = pypi::extract_source_candidate(&body).unwrap();
    let (owner, repo) = manifest::normalize_github_url(&cand).unwrap();
    assert_eq!(owner, "psf");
    assert_eq!(repo, "requests");
}

#[test]
fn test_pypi_resolver_prefers_source() {
    let body = serde_json::json!({
        "info": {
            "home_page": "https://github.com/wrong/wrong",
            "project_urls": {
                "Source": "https://github.com/right/right",
                "Homepage": "https://github.com/also-wrong/wrong"
            }
        }
    });
    let cand = pypi::extract_source_candidate(&body).unwrap();
    let (owner, repo) = manifest::normalize_github_url(&cand).unwrap();
    assert_eq!(owner, "right");
    assert_eq!(repo, "right");
}

#[test]
fn test_go_module_path_extraction() {
    assert_eq!(
        manifest::go_module_to_github("github.com/gin-gonic/gin"),
        Some(("gin-gonic".into(), "gin".into()))
    );
    assert_eq!(
        manifest::go_module_to_github("github.com/foo/bar/v2"),
        Some(("foo".into(), "bar".into()))
    );
    assert_eq!(manifest::go_module_to_github("golang.org/x/net"), None);
}

#[test]
fn test_crates_io_repository_extraction() {
    let body = serde_json::json!({
        "crate": {
            "name": "serde",
            "repository": "https://github.com/serde-rs/serde"
        }
    });
    let url = cargo::extract_crates_repository(&body).unwrap();
    let (owner, repo) = manifest::normalize_github_url(&url).unwrap();
    assert_eq!(owner, "serde-rs");
    assert_eq!(repo, "serde");
}

#[test]
fn test_manifest_discovery_finds_package_json() {
    let dir = tempdir();
    fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"lodash":"^4.17.21","react":"18.0.0"},"devDependencies":{"jest":"^29"}}"#,
    )
    .unwrap();
    let deps = manifest::discover(dir.to_str().unwrap()).unwrap();
    let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"lodash"));
    assert!(names.contains(&"react"));
    assert!(names.contains(&"jest"));
    assert!(deps.iter().all(|d| d.ecosystem == "npm"));
}

#[test]
fn test_requirements_txt_parsing() {
    let body = "# comment\nrequests==2.31.0\nflask>=2.0\n-e git+https://github.com/foo/bar\nnumpy  # inline\n";
    let deps = manifest::parse_requirements_txt(body).unwrap();
    let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, vec!["requests", "flask", "numpy"]);
}

#[test]
fn test_go_mod_block_and_indirect() {
    let body = r#"
module example.com/x

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/pkg/errors v0.9.1 // indirect
)

require github.com/stretchr/testify v1.8.0
"#;
    let deps = manifest::parse_go_mod(body, false).unwrap();
    let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"github.com/gin-gonic/gin"));
    assert!(names.contains(&"github.com/stretchr/testify"));
    assert!(
        !names.contains(&"github.com/pkg/errors"),
        "indirect should be skipped at depth 1"
    );

    let deps2 = manifest::parse_go_mod(body, true).unwrap();
    let names2: Vec<&str> = deps2.iter().map(|d| d.name.as_str()).collect();
    assert!(names2.contains(&"github.com/pkg/errors"));
}

#[test]
fn test_cargo_toml_parsing() {
    let body = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
serde = "1.0"
regex = { version = "1", features = ["std"] }
local = { path = "../local" }

[dev-dependencies]
tempfile = "3"
"#;
    let deps = manifest::parse_cargo_toml(body).unwrap();
    let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"serde"));
    assert!(names.contains(&"regex"));
    assert!(names.contains(&"tempfile"));
    assert!(
        !names.contains(&"local"),
        "path-only deps should be skipped"
    );
}

#[test]
fn test_normalize_github_url_variants() {
    let cases = [
        ("git+https://github.com/foo/bar.git", Some(("foo", "bar"))),
        ("https://github.com/foo/bar", Some(("foo", "bar"))),
        ("git@github.com:foo/bar.git", Some(("foo", "bar"))),
        ("https://gitlab.com/foo/bar", None),
        ("https://github.com/foo/bar/tree/main", Some(("foo", "bar"))),
    ];
    for (input, expected) in cases {
        let got = manifest::normalize_github_url(input);
        match expected {
            Some((o, r)) => {
                let (go, gr) = got.unwrap_or_else(|| panic!("expected Some for {input}"));
                assert_eq!((go.as_str(), gr.as_str()), (o, r), "for {input}");
            }
            None => assert!(got.is_none(), "expected None for {input}"),
        }
    }
}

#[test]
fn test_dedup_across_depths() {
    // Simulate what `run` does internally: a HashSet<(eco, name)>.
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let d1 = ("npm".to_string(), "lodash".to_string());
    let d2 = ("npm".to_string(), "react".to_string());
    let d3 = ("npm".to_string(), "lodash".to_string()); // duplicate from depth 2
    let d4 = ("cargo".to_string(), "lodash".to_string()); // different eco, NOT a duplicate
    assert!(seen.insert(d1));
    assert!(seen.insert(d2));
    assert!(!seen.insert(d3));
    assert!(seen.insert(d4));
    assert_eq!(seen.len(), 3);
}

// ---------------------------------------------------------------------------
// minimal tmpdir helper so we don't pull in tempfile crate
// ---------------------------------------------------------------------------
fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = base.join(format!("warden-audit-test-{pid}-{nanos}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
