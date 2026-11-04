# Security Policy

## Supported versions

Draincheck is pre-release. Security fixes go into the latest commit on `main` and, once
releases exist, the latest release.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion.**

Report privately through GitHub:
[Report a vulnerability](https://github.com/cyber1998/draincheck/security/advisories/new).

Include what you found, how to reproduce it and the impact you expect. We will acknowledge
your report within 5 working days, keep you updated, and credit you in the advisory unless
you ask us not to. We ask that you give us 90 days to ship a fix before public disclosure.

## What we treat as a vulnerability

Draincheck's core promise is that it stays inside a local sandbox. These are in scope:

- any code path that connects to a non-local RPC endpoint or live third-party service;
- any way to make Draincheck read, use or leak a real private key;
- a false pass: a scenario or invariant that reports "safe" when funds moved outside
  policy;
- bypasses of `.claude/hooks/guard_rpc.py`;
- the usual: code execution, path traversal or injection via scenario files or reports.

Out of scope: weaknesses in the deliberately vulnerable demo agent in
`examples/vulnerable_agent` (it is unsafe by design), and attacks that need a malicious
local user with full access to the machine.
