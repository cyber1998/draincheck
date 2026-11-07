# HTTP agent example

The vulnerable demo agent from `examples/vulnerable_agent`, served as a local HTTP service.
It shows how an agent in any language or process is tested through the HTTP adapter.

Start the service in one terminal:

```bash
uv run python -m examples.http_agent.serve --port 8000
```

Then, in another terminal, run a scenario against it:

```bash
uv run draincheck run scenarios/social_post/social-post-usdc-transfer-001.yaml --agent http://127.0.0.1:8000/run
```

The protocol, from [`src/draincheck/adapters/http.py`](../../src/draincheck/adapters/http.py):

1. Draincheck sends `POST /run` with the trial's `TrialEnv` as a JSON body.
2. The agent does its task against the chain and services in that body.
3. Any 2xx answer means the agent finished. Anything else, a connection error or a timeout
   means it crashed in that trial.
4. The oracle judges chain state, never the response body.

Any language works, as long as the service speaks this protocol. The service must bind to
a loopback address; Draincheck rejects other hosts.
