# Work Log: Sam Rivera (example)

> Append-only daily log. One row per substantive unit of work, the moment it lands:
> `| YYYY-MM-DD HH:MM | Glyph | Context | What |`. Every row self-dates; the `## {Weekday} DD.MM`
> header is a display anchor. Glyphs are the activity types from bridge-config.yaml.
> Context is the hat: `northwind` (partner), `contoso` (freelance), `household` (private).
> This is example data; see board.md for the matching task snapshot.

## Wed 23.09

<details open>
<summary>Worklog (8)</summary>

| Timestamp        | Glyph | Context | What |
|------------------|-------|---------|------|
| 2026-09-23 07:05 | 📋 | northwind | morning briefing: sync still stuck, 1 300 orders queued; freelance pipeline has 2 overdue follow-ups |
| 2026-09-23 09:40 | 📧 | northwind | drafted the key request to Max (Fabrikam warehouse IT), company signature; Sam sent it. Incident now blocked_by the key |
| 2026-09-23 10:30 | 📝 | northwind | fabrikam-sync-backlog STATUS: queue is safe, sync resumes where it stopped; added key-expiry check as next step |
| 2026-09-23 13:15 | 💻 | contoso | route export: GPX output validated against 40 staging routes, 2 edge cases fixed (empty stop, midnight crossing) |
| 2026-09-23 16:20 | 💻 | contoso | opened PR #57 in contoso-logistics/route-planner; contoso-route-export → review |
| 2026-09-23 17:00 | 🔬 | contoso | freelance pipeline: lead 1 scheduled interview 2 for 30.09.; leads 2 and 3 still silent past their follow-up date |
| 2026-09-23 20:10 | 📁 | household | tax return 2025: insurance and donation receipts filed; logbook and home-office share still open |
| 2026-09-23 21:30 | 🔧 | household | photos-travel-copy still failing (travel drive not plugged in since 09.08.); left for the morning list |

</details>

## Tue 22.09

<details>
<summary>Worklog (7)</summary>

| Timestamp        | Glyph | Context | What |
|------------------|-------|---------|------|
| 2026-09-22 06:45 | 🐛 | northwind | health digest pushed ONE red line: fabrikam-sync last success 28 h ago → opened fabrikam-sync-backlog (incident, P1) |
| 2026-09-22 08:30 | 🔬 | northwind | sync log shows 401 from the warehouse API since 02:00 on 22.09.; other endpoints fine |
| 2026-09-22 10:15 | 🐛 | northwind | root cause: Fabrikam's warehouse API key expired 21.09. (one-year validity); only Fabrikam can issue a new one |
| 2026-09-22 10:40 | 📧 | northwind | drafted incident notice to Dana (Fabrikam service owner) with impact and next step; Sam reviewed and sent |
| 2026-09-22 14:00 | 💻 | contoso | route export: CSV writer done, unit tests green |
| 2026-09-22 18:20 | 📋 | household | power price letter: 36.40 ct/kWh from November; notice deadline 01.10. noted in the contract file |
| 2026-09-22 19:05 | 📋 | household | vehicle logbook behind since 04.08.; blocks the car share in the tax return, kept in backlog until the return needs it |

</details>
