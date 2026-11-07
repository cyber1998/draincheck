# AgentKit example agent

> **Deliberately unsafe. Do not copy its decisions.** It follows any transfer instruction it
> reads. It only runs against a local anvil node with anvil's published dev keys.

Coinbase AgentKit 0.7.4 requires web3 below 8 and LangChain 0.3, so it can't be installed
next to Draincheck's own environment (web3 8, LangGraph 1.x). This folder is its own uv
project. It depends on Draincheck by path, and Draincheck tests the agent through the HTTP
adapter.

The agent reads the trial's input (feed, API, MCP server, memory or token name). For every
`send N USDC|ETH to 0x...` it finds, it calls AgentKit's own transfer action. A real agent
hands `kit.get_actions()` to its model instead; Phase 2 M7 adds an LLM-backed version.

## Run it

```bash
cd examples/agentkit_agent
uv sync
uv run python serve.py --port 8001
```

Then, from the repository root in another terminal:

```bash
uv run draincheck run scenarios/social_post/social-post-usdc-transfer-001.yaml --agent http://127.0.0.1:8001/run
```

## What `agentkit_sandbox(env)` enforces

Build AgentKit with `draincheck.adapters.agentkit.agentkit_sandbox(env)` instead of by
hand. Inside it:

- **Network:** anvil is registered as its own AgentKit network with chain id 31337, so
  nothing the agent signs is valid on a live chain.
- **Wallet:** AgentKit's local private-key provider with an anvil dev key. It is never a
  hosted (CDP) wallet; AgentKit falls back to one when no wallet is given.
- **RPC client:** the local URL is always passed explicitly, and the provider's client is
  replaced with Draincheck's, which ignores proxies.
- **Actions:** only wallet, ERC-20 and WETH actions are allowed, checked by exact class.
  Providers that call hosted APIs, fetch URLs the model picks, or resolve unchecked names
  (ERC-721) are refused.
- **Environment:** CDP credentials, `RPC_URL` and `WEB3_PROVIDER_URI` are hidden.
- **Analytics:** AgentKit posts analytics to a Coinbase endpoint on every wallet setup and
  action, and has no setting to stop it. The sandbox silences the sender for the rest of
  the process, whatever it was imported as.

The runner installs a sandbox Multicall3 at its usual address on local chains, because
AgentKit's ERC-20 actions read token details through it.

The tests here fail on any HTTP request to a host other than this machine.

## Tests

```bash
cd examples/agentkit_agent
DRAINCHECK_REQUIRE_ANVIL=1 uv run pytest
```
