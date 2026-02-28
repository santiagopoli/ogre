# OGRE Project

Secure database governance proxy built in Rust with a React/TypeScript frontend.

## Architecture

- **Backend**: Rust workspace with 7 crates (`crates/`)
  - `ogre-core` — Core types, traits, errors
  - `ogre-crypto` — ED25519 signing/verification
  - `ogre-audit` — Immutable audit log (hash chain)
  - `ogre-rules` — Rules engine (conditions + effects)
  - `ogre-connector-sqlite` — SQLite connector with pooling
  - `ogre-proxy` — Deterministic proxy orchestrating the system
  - `ogre-api` — REST API server (Axum)
- **Frontend**: React 19 + TypeScript + Vite + Tailwind CSS (`web/`)
  - Views: Dashboard, Rules, AuditLog, Connectors, Keys
  - API client at `web/src/api.ts` hits `/api/v1`

## Commands

- **Rust check**: `cargo check --workspace`
- **Rust tests**: `cargo test --workspace`
- **Crate test**: `cargo test -p <crate-name>`
- **Web build**: `cd web && npm run build`
- **Web dev**: `cd web && npm run dev`

## Conventions

- All crates use `edition = "2021"`, `thiserror` for errors, `serde` for serialization
- UUIDs v4 for identifiers, Chrono for timestamps
- Axum 0.7 for HTTP, Tokio for async runtime
- Tailwind utility classes, dark theme (`bg-gray-950`), green accent (`#22c55e`)

---

## Agent Team Roles

When working as an agent team, the following roles and rules apply.

### Senior Software Engineer (`senior-eng`)

See `.claude/roles/senior-engineer.md` for full instructions.

Core principles: Clean Code, TDD (write tests BEFORE implementation), Boy Scout Rule (leave code cleaner than you found it). Works in a git worktree. Must request plan approval from the lead before making changes. All code must compile and pass tests before marking a task complete.

### Lead Software Engineer (`lead-eng`)

See `.claude/roles/lead-engineer.md` for full instructions.

Reviews ALL work from the senior engineer before presenting to the user. Enforces code quality standards, architectural consistency, and test coverage. Rejects work that doesn't meet the bar. Acts as the team lead.

### Lead Designer (`designer`)

See `.claude/roles/lead-designer.md` for full instructions.

Owns the frontend UI/UX. Designs and implements views in `web/src/`. Ensures visual consistency, accessibility, and responsive design using Tailwind CSS. Coordinates with the lead engineer on API contracts.

### QA Engineer (`qa`)

See `.claude/roles/qa-engineer.md` for full instructions.

Tests EVERYTHING. Runs the full test suite, writes missing tests, verifies the app works end-to-end. Reports bugs as tasks with reproduction steps. Does not approve until all tests pass and edge cases are covered.
