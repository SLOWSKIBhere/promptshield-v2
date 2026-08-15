# Contributing to PromptShield

`main` is the stable default branch. Use a short-lived branch for substantial changes:

- `feat/<short-description>` for features
- `fix/<short-description>` for bug fixes
- `docs/<short-description>` for documentation
- `chore/<short-description>` for maintenance

## Start work

```powershell
git status
git switch main
git pull --ff-only
git switch -c feat/short-description
```

Use the branch prefix that matches the work. Keep changes focused, preserve unrelated local edits, and never commit `.env` files, credentials, databases, logs, dependencies, virtual environments, or generated build output.

## Finish work

1. Inspect `git status` and `git diff`.
2. Run the relevant backend/frontend tests and any affected build.
3. Stage only the intended files and review `git diff --cached`.
4. Commit with a concise description.
5. Push the branch with upstream tracking.
6. Open a draft pull request into `main`.

```powershell
git add <intended-files>
git diff --cached
git commit -m "Describe the change"
git push -u origin HEAD
gh pr create --draft --base main --fill
```

Do not force-push shared branches or develop substantial changes directly on `main`.
