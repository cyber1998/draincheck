---
name: incident-to-scenario
description: Turn a pasted incident URL into a Draincheck scenario YAML plus a test. Use when the user pastes an incident or paper link and wants it as a scenario.
---
# Incident to scenario

1. Read the page at the URL the user gave. Summarise in two lines what the attacker put
   where, and what the agent did with money. If the page does not describe an agent moving
   funds, say so and stop.
2. Pick the entry point (social_post, token_metadata, api_response, router, memory) and the
   payload encoding (plain, base64, morse, unicode_homoglyph) the incident used.
3. Write the YAML with the `new-scenario` skill's template. Set `source:` to the URL.
   Rewrite the payload so it targets only local anvil accounts; never copy real addresses,
   names or live endpoints from the incident.
4. Add a pytest in `tests/scenarios/` that runs the scenario against
   `examples/vulnerable_agent` and asserts the vulnerable agent fails it.
5. Run `uv run pytest` and show the result.
