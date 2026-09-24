---
slug: fabrikam-managed-service
type: ops
status: doing
priority: P2
created: 2025-10-01
last_updated: 2026-09-23
headline: "Fabrikam managed service: order sync operation, weekly report, incidents"
context: northwind
mandant: fabrikam
sync:
  bridge_only: false
  github:
    repo: northwind-advisory/fabrikam-ops
    project: { org: northwind-advisory, number: 3 }
---

# Fabrikam managed service (stream)

## Situation

Northwind runs Fabrikam's nightly order sync as a managed service under a
monthly retainer. The work never finishes: the weekly health report,
upkeep of the sync, incidents when they happen. It lives in
`work/streams/`, so it does not count against the WIP cap. Incidents get
their own task (currently fabrikam-sync-backlog).

## Status

Weekly report of 21.09. drafted by the home server, reviewed and sent by
Sam: 99.4 percent sync success, no open incidents at that time. Since
22.09. one P1 incident is open.

## Next Steps

- [ ] next weekly report 28.09. (drafted automatically, Sam sends)
- [ ] quarterly review with Dana in October: propose key-expiry monitoring as a change
- [ ] upgrade the sync runtime before its end of support in December
