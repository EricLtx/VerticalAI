# Trusted computing base statement (spec §5)

In scope of the invariants: the kernel daemon, its service account, the OS keyring, the interceptor chain, kernel-launched (governed) inference processes, enrolled device keys.

Outside the TCB, per platform, and surfaced in the inventory as **unmediated channels**:
- any harness that the platform cannot confine (no Job Object/AppContainer, landlock or sandbox-exec available) — it may read the store directly;
- SaaS assistants embedded inside third-party applications;
- ungoverned inference engines not launched by the kernel.

Any object reachable by an unmediated channel is treated as projected to that channel's clearance for I2 purposes; the UI says so.
