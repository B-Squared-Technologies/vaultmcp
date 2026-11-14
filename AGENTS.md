# VaultMCP

Single Go binary that runs as a PreToolUse / PostToolUse hook, detects secrets before they reach an agent transcript and swaps them for aliases. Supports Claude Code, Grok, Codex and Cursor. Public repo, see `README.md` and `CONTRIBUTING.md`.

## Commands

```
go build ./...
go test ./...
go vet ./...
```

## Repo rules

- PR into `develop`. Do not merge to `main` unless Brett asks. Bump `VERSION` with a release.
- Never put a real secret in a test or fixture. This repo is public.
- The whole fleet runs this binary in its hooks. A hook regression blocks every agent, so test install and hook paths before release.
