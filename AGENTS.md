# PromptShield Engineering Rules

- Inspect the repository tree, relevant documentation, configuration, tests, and version-control status before making changes. Verify documentation claims against the current code.
- Inspect `git status` before modifying files. Treat `main` as stable: perform substantial work on a `feat/`, `fix/`, `docs/`, or `chore/` branch created from an up-to-date `main`.
- Preserve working architecture and backward compatibility. Prefer small, reviewable changes; do not rewrite components only for stylistic consistency.
- Preserve the local React -> `/api` -> Vite proxy -> FastAPI flow and the offline fixture workflow unless a demonstrated bug requires a scoped change.
- Protect secrets: never print, log, commit, copy, or persist provider credentials or submitted target API keys. Keep local secrets in ignored environment files.
- Keep custom HTTP targets SSRF-safe. Do not weaken SSRF checks or enable private-network targets by default; private targets are development-only and require explicit opt-in.
- Automated tests must never make real provider/API calls or spend API credits. Use mocks, fakes, temporary databases, and the local fixture target.
- Do not make unrelated changes. Preserve user changes and generated/local artifacts unless their modification is explicitly requested.
- Never stage unrelated changes. Inspect the diff, stage only intended files, and prefer a draft pull request for Codex-generated changes.
- Run relevant tests before committing when applicable. Run production builds when frontend or backend build behavior may be affected, and report every failure rather than silently ignoring it.
- At task completion, report files changed, the reason for each change, commands executed, tests/builds executed with pass/fail results, remaining risks, and a suggested git commit message.
