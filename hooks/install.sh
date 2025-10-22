#!/bin/bash
# Script to install git hooks for the RsaCracker project
# This ensures that formatting and linting checks are run automatically

set -e

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_HOOKS_DIR="$(git rev-parse --git-dir)/hooks"

echo "Installing git hooks..."

# Install pre-commit hook
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    cp "$HOOKS_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
    chmod +x "$GIT_HOOKS_DIR/pre-commit"
    echo "✓ Installed pre-commit hook"
else
    echo "❌ Error: pre-commit hook not found in $HOOKS_DIR"
    exit 1
fi

# Install pre-push hook
if [ -f "$HOOKS_DIR/pre-push" ]; then
    cp "$HOOKS_DIR/pre-push" "$GIT_HOOKS_DIR/pre-push"
    chmod +x "$GIT_HOOKS_DIR/pre-push"
    echo "✓ Installed pre-push hook"
else
    echo "❌ Error: pre-push hook not found in $HOOKS_DIR"
    exit 1
fi

echo ""
echo "✓ Git hooks installed successfully!"
echo ""
echo "The following hooks will now run automatically:"
echo "  - pre-commit: Runs cargo fmt and cargo clippy before each commit"
echo "  - pre-push: Runs cargo fmt and cargo clippy before each push"
echo ""
echo "To bypass hooks (not recommended), use: git commit --no-verify"
