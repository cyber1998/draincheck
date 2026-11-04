# Contributing to Draincheck

Thanks for helping. This guide covers how to propose a change and what a pull request
needs before it can merge.

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules

Draincheck is a defensive testing tool. These rules are not negotiable, and pull requests
that break them will be closed:

- **Local sandbox only.** Every RPC URL is 127.0.0.1 / localhost. No code may reach a live
  chain, a hosted RPC provider or a live x402 facilitator.
- **No real keys.** Only anvil's published dev keys appear in code, tests or docs.
- **Your agents only.** No scenarios or code aimed at live third-party services or people.
- **The oracle judges chain state**, never the model's text.

## Before you start

- For a bug, open an issue with steps to reproduce.
- For a new feature or a large change, open an issue first so we can agree on the approach
  before you write code.
- For a new attack scenario, use the "Scenario proposal" issue template and cite a public
  source (incident write-up or paper).
- For a security problem, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Development setup

You need Python 3.12+, [uv](https://docs.astral.sh/uv/) and
[anvil](https://book.getfoundry.sh/getting-started/installation).

```bash
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

## Pull request checklist

- [ ] One logical change per pull request, on a branch from `main`.
- [ ] Tests cover the change. Every bug fix includes a test or scenario that reproduces it.
- [ ] `ruff`, `ruff format --check`, `mypy --strict` and `pytest` pass locally.
- [ ] Every public function has type hints.
- [ ] New source files start with the SPDX header:
      ```python
      # SPDX-License-Identifier: Apache-2.0
      # Copyright 2026 The Draincheck Authors
      ```
- [ ] New dependencies are justified in the pull request description.
- [ ] `CHANGELOG.md` has an entry under **Unreleased** for user-visible changes.
- [ ] You have signed the CLA (see below).

Commit messages: a short imperative summary line (under 72 characters), a blank line, then
what changed and why.

## Contributor License Agreement

Before we can merge your first pull request, you need to sign the
[Draincheck Individual Contributor License Agreement](CLA.md). You keep the copyright in
your contribution; the CLA grants the project the rights it needs to distribute it under
the Apache License 2.0 and future versions of the project's licensing.

Signing takes one comment. When you open your first pull request, the CLA bot will ask you
to post:

> I have read the CLA Document and I hereby sign the CLA

The bot records your signature and you will not be asked again. If you contribute on
behalf of your employer, make sure you have their permission to sign, as the CLA
describes.

## Licensing of contributions

Draincheck is licensed under the [Apache License, Version 2.0](LICENSE). Contributions are
accepted under the same license (Apache-2.0, section 5) and the CLA.

## Review

A maintainer will review your pull request. We aim to give a first response within a
week. Changes to `src/draincheck/oracle`, `src/draincheck/runner`, `src/draincheck/safety.py`
or `.claude/hooks/` get extra scrutiny for false passes and sandbox escapes.
