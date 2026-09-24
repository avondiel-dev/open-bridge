---
slug: fabrikam-sync-backlog
type: incident
status: doing
priority: P1
created: 2026-09-22
last_updated: 2026-09-23
headline: "Fabrikam order sync stuck since 22.09. 02:00, warehouse API key expired (P1)"
blocked_by: "Fabrikam must issue a new warehouse API key (Max Lindqvist); asked 23.09. 09:40, no reply yet"
context: northwind
mandant: fabrikam
origin: "Daily health digest went red on 22.09.: fabrikam-sync last success older than 26 hours"
sync:
  bridge_only: false
  github:
    repo: northwind-advisory/fabrikam-ops
    issues: [88]
    project: { org: northwind-advisory, number: 3 }
---

# Fabrikam: nightly order sync stuck

## Situation

The nightly sync between Fabrikam's shop and its warehouse system has not
completed since the 02:00 run on 22.09. Orders are taken in the shop but do
not reach the warehouse, so nothing ships. About 1 300 orders are queued.
Managed-service contract: P1, response within four business hours.

## Status

Root cause found 22.09. 10:15: the warehouse API rejects the sync with
401. The API key Fabrikam issued in September 2025 had a one-year
validity and expired on 21.09. Only Fabrikam's warehouse IT can issue a
new one. Incident notice to Dana drafted and sent by Sam on 22.09.; the
key request to Max drafted and sent on 23.09. 09:40. Blocked on the key.

The queue is safe: the sync reads from the shop's order table and resumes
where it stopped. Nothing is lost, only late.

## Next Steps

- [ ] follow up with Max by 24.09. 12:00 if no key has arrived (draft, not send)
- [ ] put the new key into the secret store and restart the sync
- [ ] watch the catch-up run until the queue is empty, then tell Dana (draft)
- [ ] add key expiry to the daily health digest, 30 days ahead
