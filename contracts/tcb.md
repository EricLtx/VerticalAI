# Trusted computing base statement (spec §5)

In scope of the invariants: the kernel daemon, its service account, the OS keyring, the interceptor chain, kernel-launched (governed) inference processes, enrolled device keys.

Outside the TCB, per platform, and surfaced in the inventory as **unmediated channels**:
- any harness that the platform cannot confine (no Job Object/AppContainer, landlock or sandbox-exec available) — it may read the store directly;
- SaaS assistants embedded inside third-party applications;
- ungoverned inference engines not launched by the kernel.

Any object reachable by an unmediated channel is treated as projected to that channel's clearance for I2 purposes; the UI says so.

## Arch adapters (SP1b)

### Claude Code adapter

Pure completion, no tools. The kernel launches the installed `claude` with every built-in tool removed (`--tools ""`), MCP connectors off (`--safe-mode --strict-mcp-config`), one turn (`--max-turns 1`) and no session written to disk (`--no-session-persistence`); the prompt goes in on stdin, so no process list on this machine shows it. The child runs in one fixed, empty directory (`<state_dir>/claude-code-cwd`, `0700` on Unix), which is also the only directory it could reach if a tool were ever re-enabled.

The inference itself is **not governed**: it happens on Anthropic's servers, where no interceptor of ours runs. The manifest says so — `governed: false`, `locality: Cloud`, `jurisdiction: "US"`, `retention_days: 30`, clearance capped at Business with third-party data refused — so I2 refuses to lower anything above that into it. **Egress to Anthropic is not observed in SP1b**: this node records what it sent and what came back, not what the far end did with it.

Subscription use is the founder's own. A claude.ai subscription is a person's, not a product's: nothing is billed per call, so the manifest's `cost_per_1k_tokens_eur` is `0` and the list-price equivalent the CLI reports rides on the `infer` event as `cost_list_usd`, visibly a comparison and not a charge. **Customer nodes use API arches** (task 2b), which carry a key, a per-token price and, for the EU jurisdiction, a different host.

### Ollama adapter

The first **governed** arch, and the only one so far: the kernel starts the container itself (`docker run -d --name vk-ollama -p 127.0.0.1:11434:11434 -v vk-ollama:/root/.ollama --memory 12g --cpus 6 ollama/ollama:0.33.3`), so the inference is a process this node launched, capped at 12 GiB of memory and 6 CPUs, published on loopback only, with the weights in a volume it owns. `governed: true` is claimed only after the caps have been read *back* off the running container (`HostConfig.Memory`, `HostConfig.NanoCpus`): a container running without them is not a governor, whatever it was meant to be started with. `vk mount ollama --external URL` mounts an Ollama this node did not start — that one is `governed: false`, clearance capped at Business with third-party data refused, and it is an **ungoverned inference engine** in the sense of the list above.

Nothing about a governed call leaves the machine: `locality: Local`, `jurisdiction: "local"`, `retention_days: 0`, clearance up to Personal, `cost_per_1k_tokens_eur: 0` and no `cost_list_usd` — a model on this CPU is not billed and has no list price to compare against. What is **not** claimed: the container is a resource governor, not a sandbox around what the model says. Nothing inspects the completion.

Identity is content-addressed — the arch id hashes the weights' digest from `/api/tags`, the family, parameter size and quantisation, the Ollama version, `num_ctx` and the seed. The caps are deliberately outside it: the same model under a tighter cap is the same model, only slower.

**Its context ceiling is half the window asked for.** Ollama 0.33.3 cuts an oversize prompt to `num_ctx / 2 + 3` tokens and answers HTTP 200 with `done_reason: "stop"` and no error (spike 1a). So the manifest's ceiling is `min(num_ctx, context_length) / 2`; a prompt past nine tenths of that is refused before the call, and an answer whose `prompt_eval_count` reached `num_ctx / 2` is refused after it. Both are I4′: a confident answer to half a question is the failure this invariant exists to prevent.
