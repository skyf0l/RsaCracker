# Copilot instructions for this repository

Repository context
- Rust (Cargo) project for RSA key analysis with a CLI.
- Pattern for new “attack” features: add parameters and parsing, implement module based on an existing attack, export/register, wire CLI flags, update docs, add tests.

Goals and scope
- Small, focused PRs (one feature/fix).
- Prioritize correctness, determinism, and security.
- Follow existing structure and naming; extend established patterns.

New attacks: required steps
1) Parameters: add field(s) to Parameters and parsing (e.g., from_raw); implement Display/defaulting.
2) Module: create src/attacks/<attack_name>.rs modeled on a similar attack.
3) Wiring: export in src/attacks/mod.rs and register in the attack list/dispatcher.
4) CLI: add flags (short/long) and validate incompatible/required combinations.
5) Tests: unit tests for logic; integration test for CLI if applicable; keep randomness deterministic.
6) Docs: update README and examples (and ensure --help reflects changes).

Quality gates (MUST pass before ANY commit/report_progress)
- **ALWAYS** run `cargo fmt --all` before committing (no exceptions).
- **ALWAYS** run `cargo clippy --all-targets --all-features` and fix ALL warnings before committing (or add narrowly scoped #[allow] with justification).
- **ALWAYS** run `cargo test --all --all-features` and ensure all tests pass (deterministic and passing).
- CLI --help and README match behavior and flags.
- No regressions in output format without documentation.

Coding standards
- Error handling: avoid panics for user/file input; prefer Result with clear context (use existing error approach).
- Logging/UX: human-friendly messages, minimal noise by default; maintain stable output for scripting.
- Performance: avoid unnecessary clones/allocations on big integers/byte buffers; use slices/iterators; document non-obvious optimizations.
- Security: use vetted crypto crates only; no custom crypto; avoid unsafe unless essential and justified.

Dependency management
- Keep bumps minimal and scoped; review upstream CHANGELOGs.
- Verify feature flag changes and MSRV before merging (e.g., rand_core ≥ 0.9 uses feature "os_rng", not "getrandom").
- Ensure versions are not yanked; note semver impacts in PR body.

PR hygiene
- Branch names: feature/<desc>, fix/<desc>, chore/<scope>.
- Conventional Commits for messages (feat:, fix:, chore:, refactor:, test:, docs:).
- PR body includes: Summary, Scope, Testing, Compatibility, Docs, Perf/Security notes.

Non-goals (open an issue first)
- Broad refactors across unrelated modules.
- Changing MSRV, crate structure, or fundamental CLI behavior.
- Introducing new crypto primitives or nonstandard algorithms.

Copilot coding agent workflow
- Pre-flight: map the request to files/modules; choose a similar attack as a template.
- Implement: follow “New attacks: required steps”.
- **Verify (MANDATORY before every report_progress):**
  1. Run `cargo fmt --all` (zero tolerance for unformatted code)
  2. Run `cargo clippy --all-targets --all-features` (fix ALL warnings)
  3. Run `cargo test --all --all-features` (all tests must pass)
  4. Manual CLI checks for common and edge cases
- Open PR: concise title, complete PR body checklist, link related issues.
