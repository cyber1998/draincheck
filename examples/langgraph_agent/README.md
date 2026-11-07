# LangGraph agent example

A LangGraph agent wired to Draincheck through the LangGraph adapter. The "model" is
`NaiveChatModel`, a deterministic stand-in that obeys every instruction it reads. It is a
canary, like `examples/vulnerable_agent`: it exists so CI exercises the LangGraph path without
a real model. Do not copy its design.

The adapter needs the extra:

```bash
pip install 'draincheck[langgraph]'
```

Run a scenario against the example graph:

```bash
uv run draincheck run scenarios/social_post/social-post-usdc-transfer-001.yaml --agent langgraph:examples.langgraph_agent.agent:make_graph
```

## The factory

Your factory is called once per trial:

```python
def make_graph(env: TrialEnv, tools: list[BaseTool]) -> CompiledStateGraph: ...
```

- `env` is the trial's `TrialEnv`: the local RPC URL, the agent's dev key and address, the
  task, the services (name to local URL) and the contracts (name to address).
- `tools` are the sandbox wallet as LangChain tools (listed below).

It returns anything with `.invoke({"messages": [...]}, config)`, normally a compiled
LangGraph graph. Draincheck invokes it with the trial's task as the first user message, then
judges what happened on chain. The agent's own text is never judged.

To test a real model, swap it in:

```python
from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent


def make_graph(env, tools):
    return create_react_agent(ChatAnthropic(model=...), tools)
```

## The tools

| Tool | Arguments | What it does |
|---|---|---|
| `read_service` | `name` | Reads one of your services (pays an x402 fee if it asks) |
| `token_info` | `token_address` | The name and symbol the token reports |
| `balance` | `token_address` (optional) | Your ETH in wei, or a token's balance in base units |
| `send_eth` | `to`, `amount_eth` | Sends ETH |
| `send_token` | `token_address`, `to`, `amount` | Sends whole tokens; `"USDC"` is allowed |
| `approve` | `token_address`, `spender`, `amount` | Approves a spender; `"max"` means unlimited |
| `swap` | `router`, `token_in`, `token_out`, `amount`, `min_out` | Swaps through a router |

Amounts are whole tokens as strings (`"12.5"`), not base units.
