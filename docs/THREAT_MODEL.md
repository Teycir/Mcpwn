# Mcpwn Threat Model

## 1. What Mcpwn tests

Mcpwn is an **offensive scanner for MCP servers**. It assumes the operator is
authorized to launch the server (stdio) or connect to the endpoint (HTTP) and
that the server may be malicious, vulnerable, or both.

Out of scope: the calling LLM/agent runtime, the MCP client application's UI,
network infrastructure, and the security of third-party dependencies beyond
what they expose through MCP.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Host filesystem | Tool arguments may reach file APIs or shells |
| Credentials and tokens | Often present in server metadata, env or responses |
| Network position | SSRF can reach localhost, metadata services, internal APIs |
| Agent context | Tool descriptions and outputs are fed to an LLM |
| Server availability | Flooding and parser bugs can deny service |
| Authorization state | Tool calls may act with the server's privileges |

## 3. Actors and trust boundaries

```
operator ──launches──> MCP server <──stdio/HTTP──> Mcpwn
                           │
                           ├── tools / resources / prompts (untrusted metadata)
                           ├── host OS, filesystem, network (privileged)
                           └── calling agent (trusts tool output)
```

- **Server metadata is untrusted.** Names, descriptions, schemas, defaults and
  instructions are attacker-controlled in a compromised or malicious server.
- **Tool output is untrusted.** It may reflect payloads, contain Markdown,
  credentials, or instructions aimed at the calling model.
- **Mcpwn is trusted by the operator but must not leak secrets.** Evidence is
  redacted; reports can be shared.
- **The target is not trusted to be well-behaved.** Every transport operation
  is bounded and every crash claim requires liveness evidence.

## 4. Attack surface and coverage

| Surface | Threats | Mcpwn module | Mode |
|---|---|---|---|
| Argument handling | Command injection, file read | `tool_injection` | active |
| Resource URIs | Path traversal | `resource_traversal` | active |
| Tool metadata | Hidden instructions, poisoning, impersonation | `tool_poisoning` | passive |
| Metadata/secrets | Credential leakage in descriptions/defaults | `credential_exposure` | passive |
| Tool graph | Read + network exfiltration chains | `attack_chains` | passive |
| Identity parameters | IDOR, confused deputy, role mass assignment | `confused_deputy` | active |
| HTTP authorization | Missing auth, token replay, JWT bypass | `auth_bypass` | active (HTTP) |
| URL parameters | SSRF to loopback/metadata | `ssrf_injection` | active |
| Command output | OOB DNS exfiltration | `oob_detection` | active |
| Output rendering | Markdown/link injection, delimiter breakout | `prompt_injection` | active |
| JSON/object args | Prototype/schema pollution | `schema_pollution` | active |
| Serialized args | Unsafe deserialization | `deserialization` | destructive |
| Protocol lifecycle | Skip/double initialize | `state_desync` | active |
| Capability negotiation | Malformed capabilities, unknown methods, undeclared notifications | `capability_fuzzing`, `capability_abuse` | active (fuzzing destructive-gated) |
| JSON-RPC parser | Crashes, error leaks | `protocol_fuzzing` | active |
| Concurrency | Duplicate creation, lock errors | `race_condition` | destructive |
| Resource creation | Subscription/memory exhaustion | `subscription_flood` | destructive |
| Payload size/depth | Oversized args, recursion, batch bombs | `resource_exhaustion` | destructive |
| Timing/behavior | Side channels, shell/network indicators | `side_channel` | active (low confidence) |

## 5. Evidence and confidence policy

A finding has independent **severity** and **confidence**.

| Claim | Minimum evidence |
|---|---|
| RCE (`confirmed`) | Reproduced command output (`uid=`, `root:x:`) on two probes |
| Path traversal (`confirmed`) | File markers returned twice for the same URI/argument |
| SSRF (`confirmed`) | Callback received by the controlled listener, or canary returned |
| Missing auth (`confirmed`) | Authenticated baseline and unauthenticated request both return data |
| Blind injection | Reproducible delay vs baseline + control; **not** confirmed RCE |
| Timing side channel | Consistent timing difference; `possible`, low severity |
| Tool poisoning | Static hidden characters/instructions; requires manual review |
| Attack chain | Capability composition only; never executed |

Rules enforced in code:

- An unverified finding cannot exceed 84% confidence.
- Timing findings have `TIMING*` types and never inherit an RCE title.
- No crash is reported without the process being dead or two failed pings.
- A capability that is merely accepted (spec-compliant leniency) is not a vuln.
- Reflection of a payload is informational, not injection.

## 6. Safety controls

| Control | Default | Purpose |
|---|---|---|
| `--allow-destructive` | off | Gate flooding, exhaustion, deserialization timing probes |
| `--safe-mode` | off | Disable destructive and fuzzing suites |
| `--max-requests` | 20000 | Global request budget |
| `--max-concurrency` | 8 | Bound worker threads |
| `--max-payload-bytes` | 1 MiB | Bound probe size |
| `--flood-count` | 200 | Bound subscriptions |
| Loopback listeners | yes | SSRF/DNS callbacks stay local unless `--oob-callback-base` |
| Cleanup | `finally` | Close listeners, restart or stop servers |

## 7. Non-goals and residual risk

- Mcpwn cannot prove the absence of a vulnerability.
- Static metadata findings can be false positives; they are marked as such.
- A malicious server can lie, delay, or behave differently under test.
- Timing analysis is statistically weak on shared/noisy hosts.
- Authorization testing requires credentials in `--header`; without them only
  an unauthenticated observation is reported.
- The tool does not test the agent's prompt handling end to end; it tests what
  the server exposes to the agent.
