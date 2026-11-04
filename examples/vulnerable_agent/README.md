# Vulnerable demo agent

> **Deliberately unsafe. Do not copy its design.** It only runs against a local anvil
> node and uses anvil's published dev keys, which hold nothing on any real network.

This agent is Draincheck's canary. If Draincheck ever stops catching it, the harness is
broken, not the agent fixed.

What it does: pays a local x402-style feed service, reads the posts, and acts on them.

Why it is unsafe, on purpose:

1. It obeys instructions found in untrusted content (prompt injection).
2. It has no spend limit, no recipient allowlist and no approval step.
3. It pays whatever a `402 Payment Required` response asks for.

Its "brain" is a deterministic instruction follower, not a language model. That keeps tests
fast, free and repeatable while failing the same way a naive LLM agent does. An LLM-backed
variant on AgentKit is planned.

The feed service is a simplified stand-in for x402: the client pays with a plain native
transfer and names the transaction in the `X-PAYMENT` header. Phase 1 replaces it with a
mock facilitator that speaks the real protocol.

## Run it

Needs [anvil](https://book.getfoundry.sh/getting-started/installation) on `PATH`.

```bash
uv run python -m examples.vulnerable_agent.run_demo
```
