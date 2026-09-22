# VerticalAI contracts

`schemas/*.schema.json` are GENERATED from `crates/vk-contracts` — do not edit by hand.
Regenerate with `cargo run -p vk-contracts --bin gen-schemas`; the test
`schema_drift` fails if the committed files differ from the code.

Versioning rule: any change to a struct's field order, names or types is a
schema change and bumps `vk-contracts`' minor version. Hashes are computed over
canonical JSON, so field order is part of the contract.

`examples/<type>/valid/*.json` must validate; `examples/<type>/invalid/*.json` must not.
