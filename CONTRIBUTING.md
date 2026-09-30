# Contributing

Thanks for your interest! This is an early prototype, so keep changes small and focused.

1. **Stdlib only.** The runtime has no third-party dependencies; please keep it that way unless the change has been discussed in an issue first.
2. **Python 3.11+.** CI runs on 3.11 and 3.12.
3. **Tests are required.** Run them from the repo root before you open a PR:
   ```bash
   python3 -m unittest discover -s tests
   ```
   Tests use local fixture servers only, so no internet access is needed.
4. **Lint:** `pip install ruff && ruff check --select E9,F63,F7,F82 .` (the same check CI runs).
5. **No secrets** in commits, issues or test fixtures. For security issues, see [SECURITY.md](SECURITY.md).
6. Use clear commit messages, and link one issue per PR where possible.

By contributing, you agree that your contributions are licensed under the MIT License.
