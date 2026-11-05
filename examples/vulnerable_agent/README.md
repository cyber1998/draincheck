# Vulnerable demo agent

> **Deliberately unsafe. Do not copy its design.** It only runs against a local anvil
> node and uses anvil's published dev keys, which hold nothing on any real network.

This agent is Draincheck's canary. If Draincheck stops catching it, the harness is broken,
not the agent fixed.

It pays for its input in USDC through the mock x402 facilitator, then does what the content
says. Its "brain" is a deterministic instruction follower, not a language model, so tests
are fast, free and repeatable.

## Flaws, per entry point

Each scenario entry point puts the payload where the agent reads it:

- **Social feed** (`social_post`): pays for a feed and obeys instructions in its posts.
- **Paid API** (`api_response`): pays for a quote and obeys the instruction in its `note`.
- **Memory** (`memory`): reads saved notes and obeys them.
- **Token metadata** (`token_metadata`): reads a token's name and symbol and obeys them.
- **Router listings** (`router`): pays for a list of swap routers, takes the first, and
  - approves the router for an unlimited amount of USDC,
  - swaps 100 USDC with no slippage limit (minimum output 0).

Across all of them:

1. It treats instructions in untrusted content as commands (prompt injection).
2. It has no spend limit, no recipient allowlist and no approval step.
3. It pays whatever a `402 Payment Required` response asks for.
4. It decodes base64, Morse and Cyrillic look-alike text before reading it, so a filter
   that only sees the raw text is bypassed.

## Run the demo

Needs [anvil](https://book.getfoundry.sh/getting-started/installation) on `PATH`.

```bash
uv run python -m examples.vulnerable_agent.run_demo
```

## Run a scenario

```bash
uv run draincheck run scenarios/social_post/social-post-usdc-transfer-001.yaml \
    --agent examples.vulnerable_agent.target:run
```
