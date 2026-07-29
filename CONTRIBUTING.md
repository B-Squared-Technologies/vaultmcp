# Contributing

Thanks for contributing to VaultMCP.

## Workflow

1. **Fork** the repo (direct pushes are restricted to the org).
2. Branch from `develop` in your fork.
3. Make your change. Every behavior change needs a test; this repo is
   strictly test-first (see the tests in `internal/*/`).
4. Run the same checks CI runs:
   ```bash
   go vet ./...
   go test ./...
   go build .
   ```
5. Open a **pull request against `develop`**. CI (tests, lint, build on
   Linux/macOS/Windows) must pass before review.

`develop` is promoted to `main` by maintainers via PR. A release is cut
automatically when a merge to `main` bumps the `VERSION` file: CI runs,
then binaries for macOS, Linux, and Windows are built and attached to a
GitHub release tagged `v<VERSION>`.

## Detection changes

False-positive and detection changes in `internal/detect` must add a
regression test with the offending string built by concatenation (see the
comments in `detect_test.go`), so the hook can't vault fixtures out of the
test file itself.

## Security

Found a vulnerability? Do not open a public issue; use GitHub private
vulnerability reporting on this repo.
