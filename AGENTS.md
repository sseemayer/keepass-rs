# AGENTS - Guidelines for agent contributors

## Build / Lint / Test
- Build: `cargo build --all` or `cargo build --release` for optimized builds.
- Run all tests: `cargo test --all`.
- Run a single test: `cargo test -- test_name` (use full or partial test name; add `-- --nocapture` to see stdout).
- Run a single test file/module: `cargo test --test <test_binary_name>` or `cargo test <module>::<submodule>::<test_name>`.
- Format: `cargo fmt` (project uses `rustfmt` in dev-dependencies).

## Code style
- Formatting: run `cargo fmt` before commits; repo uses `rustfmt.toml` to configure rules.
- Imports: prefer explicit imports (e.g., `use crate::db::open::...`) and group by std -> external -> crate.
- Types: prefer explicit concrete types in public APIs; use `Option`/`Result` for nullable/ error returns.
- Naming: follow Rust conventions: `snake_case` for functions/variables, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for consts.
- Error handling: return typed errors (use `thiserror` for custom error enums); avoid `unwrap()`/`expect()` in library code.
- Safety: minimize `unsafe` usage; document and encapsulate unsafety when necessary.
- Tests: keep tests deterministic and small; use `tests/resources/` for fixtures.

