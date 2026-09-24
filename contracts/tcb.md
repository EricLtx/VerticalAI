# Trusted computing base statement (spec §5)

In scope of the invariants: the kernel daemon, its service account, the OS keyring, the interceptor chain, kernel-launched (governed) inference processes, enrolled device keys.

Outside the TCB, per platform, and surfaced in the inventory as **unmediated channels**:
- any harness that the platform cannot confine (no Job Object/AppContainer, landlock or sandbox-exec available) — it may read the store directly;
- SaaS assistants embedded inside third-party applications;
- ungoverned inference engines not launched by the kernel.

Any object reachable by an unmediated channel is treated as projected to that channel's clearance for I2 purposes; the UI says so.

## Claude Code adapter (SP1b)

Pure completion, no tools. The kernel launches the installed `claude` with every built-in tool removed (`--tools ""`), MCP connectors off (`--safe-mode --strict-mcp-config`), one turn (`--max-turns 1`) and no session written to disk (`--no-session-persistence`); the prompt goes in on stdin, so no process list on this machine shows it. The child runs in one fixed, empty directory (`<state_dir>/claude-code-cwd`, `0700` on Unix), which is also the only directory it could reach if a tool were ever re-enabled.

The inference itself is **not governed**: it happens on Anthropic's servers, where no interceptor of ours runs. The manifest says so — `governed: false`, `locality: Cloud`, `jurisdiction: "US"`, `retention_days: 30`, clearance capped at Business with third-party data refused — so I2 refuses to lower anything above that into it. **Egress to Anthropic is not observed in SP1b**: this node records what it sent and what came back, not what the far end did with it.

Subscription use is the founder's own. A claude.ai subscription is a person's, not a product's: nothing is billed per call, so the manifest's `cost_per_1k_tokens_eur` is `0` and the list-price equivalent the CLI reports rides on the `infer` event as `cost_list_usd`, visibly a comparison and not a charge. **Customer nodes use API arches** (task 2b), which carry a key, a per-token price and, for the EU jurisdiction, a different host.
