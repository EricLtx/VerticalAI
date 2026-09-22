# Federation trust roles (spec §4.4, D10)

| Role | Key location | Threshold | Signs |
|---|---|---|---|
| root | offline; founder + independent custodian + sealed recovery share | 2 of 3 | the set of role keys and their expiry |
| targets | online, per signer; short-lived delegations from root | 1 | module manifests admitted to a vertical scope |
| timestamp | online; automated | 1 | freshness of the current targets set; nodes fail closed after `max_age` |
| revocation | any root or targets key | 1 | revocation events; propagate and win merges |

Signer admission: a one-time legal-entity check by the root holders, recorded as a `targets.delegated` event. Usage evidence is never a basis for signing rights (Sybil-attackable). Progressive delegation to businesses is a targets delegation under the same roles.

The root document format is `tuf_root.schema.json` (`SignedRoot`); verification is `SignedRoot::verify` in `vk-contracts::federation` — expired roots fail closed, and fewer than `threshold` valid signatures is a rejection.
