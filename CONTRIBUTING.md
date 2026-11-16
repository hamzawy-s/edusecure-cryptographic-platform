# Contributing to EduSecure

Thanks for helping improve EduSecure. Contributions should preserve the project's educational scope and accurately describe what the implementation does.

## Development setup

1. Use Python 3.10+ and Node.js/npm.
2. Create and activate a virtual environment, then install `requirements.txt`.
3. Run `python scripts/init_keys.py` to create local development key and certificate files.
4. Run `python scripts/seed_demo.py` only if you need local demo accounts. It prints newly generated passwords once.
5. In `frontend/`, run `npm ci` and `npm run build`.

See the complete [Windows and Linux setup instructions](README.md#local-setup).

## Before opening a pull request

- Run `python -m pytest backend/tests -q`.
- Run `npm ci` and `npm run build` from `frontend/`.
- Describe behavior changes and any security assumptions in the pull request.
- Update documentation when cryptographic behavior, setup, or limitations change.
- Keep generated keys, certificates, databases, `.env` files, local storage, and credentials out of commits. Check `git status` and staged files before pushing.
- Never include real personal data, credentials, or production secrets in test fixtures or screenshots.

Please keep changes focused and avoid claiming that a control is production-ready unless it has been independently engineered and reviewed for that use.
