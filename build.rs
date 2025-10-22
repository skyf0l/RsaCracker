use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Skip hook installation in CI environment (for testing/release builds)
    // unless explicitly requested via INSTALL_GIT_HOOKS=1
    if env::var("CI").is_ok() && env::var("INSTALL_GIT_HOOKS").is_err() {
        return;
    }

    // Skip if building from a source tarball (no git directory)
    if env::var("CARGO_PKG_VERSION").is_ok() && env::var("CARGO").is_ok() {
        // We're in a cargo build, proceed to check for git
    } else {
        return;
    }

    // Check if we're in a git repository
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output();

    let git_dir = match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => return, // Not in a git repo, skip hook installation
    };

    let hooks_dir = Path::new(&git_dir).join("hooks");
    let repo_hooks_dir = Path::new("hooks");

    // Check if our hooks directory exists
    if !repo_hooks_dir.exists() {
        return;
    }

    // Install pre-commit hook
    let pre_commit_src = repo_hooks_dir.join("pre-commit");
    let pre_commit_dst = hooks_dir.join("pre-commit");
    if pre_commit_src.exists() {
        if let Ok(content) = fs::read(&pre_commit_src) {
            // Only install if not already present or different
            let should_install =
                !pre_commit_dst.exists() || fs::read(&pre_commit_dst).ok() != Some(content.clone());

            if should_install {
                let _ = fs::write(&pre_commit_dst, &content);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&pre_commit_dst, fs::Permissions::from_mode(0o755));
                }
                println!("cargo:warning=Installed git pre-commit hook");
            }
        }
    }

    // Install pre-push hook
    let pre_push_src = repo_hooks_dir.join("pre-push");
    let pre_push_dst = hooks_dir.join("pre-push");
    if pre_push_src.exists() {
        if let Ok(content) = fs::read(&pre_push_src) {
            // Only install if not already present or different
            let should_install =
                !pre_push_dst.exists() || fs::read(&pre_push_dst).ok() != Some(content.clone());

            if should_install {
                let _ = fs::write(&pre_push_dst, &content);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&pre_push_dst, fs::Permissions::from_mode(0o755));
                }
                println!("cargo:warning=Installed git pre-push hook");
            }
        }
    }
}
