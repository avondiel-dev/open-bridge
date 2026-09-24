---
slug: vehicle-logbook-q3
type: admin
status: backlog
priority: P3
created: 2026-09-16
last_updated: 2026-09-16
headline: "Car logbook behind since 04.08.: reconstruct Q3 trips from calendar and charging log"
context: household
origin: "The 2025 tax return needs the business share of the car"
sync:
  bridge_only: true
related:
  - ../../../identity/vehicles/ex-sr-42e.yaml
---

# Vehicle logbook: catch up Q3

## Situation

The logbook for `EX-SR 42E` has no entries since 04.08. The car is mixed
use (identity/vehicles/ex-sr-42e.yaml): Contoso on-site days are business,
the rest is private. Without the entries the business share for the tax
return cannot be claimed.

## Status

Not started. The trips can be reconstructed: Contoso on-site days are in
the calendar, the odometer readings are on the charging log.

## Next Steps

- [ ] list the Contoso on-site days from 04.08. to 30.09.
- [ ] match them against the charging log's odometer readings
- [ ] fill the logbook, then unblock the gap in tax-return-2025
