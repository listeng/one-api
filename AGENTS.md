# Repository Guidelines

## Project Structure & Module Organization
- `main.go` boots the API server and wires routing, middleware, and persistence.
- `controller/`, `relay/`, `router/`, and `middleware/` hold HTTP handlers, channel adaptors, and shared request flow.
- Domain helpers sit in `common/`, `model/`, and `monitor/`; static assets live in `public/` and localization strings in `i18n/`.
- Front-end themes ship under `web/`; run `web/build.sh` to rebuild bundles into `web/build/`.

## Build, Test, and Development Commands
- `go run .` starts the API using values from `.env` or environment variables.
- `go build ./...` produces a release-ready binary in the repository root; copy alongside `config.yaml` if packaging.
- `go test ./...` runs the Go suite; add `-run Relay` or similar to target specific adaptor logic.
- `cd web/air && npm install && npm start` serves the default React theme; use `./web/build.sh` to bundle all themes.

## Coding Style & Naming Conventions
- Run `gofmt -w` (or `goimports`) on all Go files; keep package names lowercase and prefer camelCase identifiers.
- Config keys and environment variables follow uppercase snake case, matching `.env.example`.
- React code in `web/` follows the included Prettier config (single quotes) and React Scripts ESLint defaults.

## Testing Guidelines
- Extend existing table-driven Go tests (see `relay/adaptor_test.go`) and assert both happy-path and fallback behavior.
- Keep mocked HTTP clients or fixtures in the same package to avoid cross-package leakage.
- For UI work, add or update `npm test` cases under the active theme and attach screenshots when behavior changes.

## Commit & Pull Request Guidelines
- Follow the repo’s short, present-tense commit messages (often Chinese summaries such as “修正转发路径”).
- Ensure each PR includes `close #123` style issue linking plus a self-test screenshot or terminal output per `pull_request_template.md`.
- Describe rollout or config implications in the PR body so operators can mirror `.env` or channel updates.

## Configuration & Deployment Notes
- Start from `.env.example`, then set database (`SQL_DSN`), cache, and external channel credentials explicitly.
- `docker-compose up -d` provides a quick local stack; remember to persist `/data` when running SQLite in containers.
- Register new UI themes in `common/config/config.go` and `web/THEMES` so the server exposes them to admins.
