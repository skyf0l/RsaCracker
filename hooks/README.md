# Git Hooks

This directory contains git hooks that help maintain code quality by automatically running formatting and linting checks.

## Available Hooks

### pre-commit
Runs before each commit to ensure:
- Code is properly formatted (`cargo fmt --all --check`)
- No clippy warnings exist (`cargo clippy --all-targets --all-features -- -D warnings`)

### pre-push
Runs before each push as an additional safeguard to ensure:
- Code is properly formatted (`cargo fmt --all --check`)
- No clippy warnings exist (`cargo clippy --all-targets --all-features -- -D warnings`)

## Installation

### Automatic Installation

**The hooks are automatically installed when you build the project** with `cargo build`, `cargo test`, or `cargo run`. No manual setup is required!

The build script (`build.rs`) automatically detects if you're in a git repository and installs the hooks if they're not already present.

### Manual Installation

If needed, you can also manually install the hooks:

```bash
./hooks/install.sh
```

This will copy the hooks to your `.git/hooks` directory and make them executable.

## Bypassing Hooks

While not recommended, you can bypass hooks in emergencies using:

```bash
git commit --no-verify
git push --no-verify
```

However, the CI pipeline will still enforce these checks, so any commits that don't pass formatting and linting will fail in CI.

## Manual Checks

You can manually run the same checks that the hooks perform:

```bash
# Check formatting
cargo fmt --all --check

# Fix formatting
cargo fmt --all

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```
