# Acceptance evidence index

Summary: 38 no evidence yet, 10 passed.

Generated 2026-10-06T02:48:08+00:00 by `tests/_harness/evidence.py` (`make acceptance MILESTONE=...`). Do not edit by hand. Simulated, staging and field results are different evidence classes: the `sim` column marks simulator-backed runs.

| AT | Milestone | Scenario | Outcome | sim | Commit | Date | Evidence |
|---|---|---|---|---|---|---|---|
| AT-01 | M0 | A user moves from Society A to Society B and replays object IDs that belong to A | passed | yes | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-01.json](AT-01.json) |
| AT-02 | M0 | A non-resident owner asks for the visitor history of their tenant | passed | yes | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-02.json](AT-02.json) |
| AT-03 | M0 | A guest request is pending and two family members decide at the same moment | passed | yes | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-03.json](AT-03.json) |
| AT-04 | M0 | An approval request times out and a queued approval from a phone arrives afterwards | passed | yes | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-04.json](AT-04.json) |
| AT-05 | M1 | A guest QR is consumed at one gate and then presented at a second, isolated gate | passed | yes | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-05.json](AT-05.json) |
| AT-06 | M1 | The WAN stays down for 72 hours including device and gateway restarts | passed | yes | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-06.json](AT-06.json) |
| AT-07 | M1 | The gateway fails while the LAN is partitioned | passed | yes | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-07.json](AT-07.json) |
| AT-08 | M1 | A device wall clock is moved backwards | passed | yes | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-08.json](AT-08.json) |
| AT-09 | M2 | The relay acknowledgement is lost after the barrier was commanded to open | no evidence yet | | | | |
| AT-10 | M2 | A safety loop or photocell detects an obstruction | no evidence yet | | | | |
| AT-11 | M1 | A resident's phone is force-stopped or notification permission is denied | no evidence yet | | | | |
| AT-12 | M1 | A domestic worker loses one of three employers | no evidence yet | | | | |
| AT-13 | M1 | A parcel pickup is attempted twice | no evidence yet | | | | |
| AT-14 | M1 | The same invoice batch is submitted twice | no evidence yet | | | | |
| AT-15 | M1 | A payment callback repeats or arrives out of order | no evidence yet | | | | |
| AT-16 | M1 | The gross settlement less fees differs from the bank credit | no evidence yet | | | | |
| AT-17 | M1 | Two operators allocate the same receipt concurrently | no evidence yet | | | | |
| AT-18 | M1 | An invoice in a closed period needs correction | no evidence yet | | | | |
| AT-19 | M2 | Vendor bank details are changed and approved by the same person | no evidence yet | | | | |
| AT-20 | M2 | 200 users try to book 10 amenity slots | no evidence yet | | | | |
| AT-21 | M2 | Binding voting is switched on without an approved legal pack | no evidence yet | | | | |
| AT-22 | M1 | A treasurer tries to restrict entry or an essential service because of debt | no evidence yet | | | | |
| AT-23 | M1 | An erasure request arrives while a legal hold applies | no evidence yet | | | | |
| AT-24 | M1 | A deleted visitor record reappears from a stale device or a backup | no evidence yet | | | | |
| AT-25 | M1 | A malicious document instructs the AI to export data about neighbours | no evidence yet | | | | |
| AT-26 | M1 | An AI proposal is confirmed after the user's role or the target has changed | no evidence yet | | | | |
| AT-27 | M2 | A Q&A question has no authoritative document behind it | no evidence yet | | | | |
| AT-28 | M2 | OCR confuses 8,000 rupees with 80,000 rupees on a vendor bill | no evidence yet | | | | |
| AT-29 | M1 | The AI provider is unavailable or the society's AI budget is exhausted | no evidence yet | | | | |
| AT-30 | M3 | A meter resets or its messages are duplicated | no evidence yet | | | | |
| AT-31 | M3 | The EV site meter goes stale or a phase is overloaded | no evidence yet | | | | |
| AT-32 | M1 | A committee term ends while a privileged session is active | no evidence yet | | | | |
| AT-33 | M1 | The full financial export is re-imported into an external system | no evidence yet | | | | |
| AT-34 | M1 | Restore after a regional-service incident | no evidence yet | | | | |
| AT-35 | M1 | A low-vision user and a guard in a new language perform core tasks | no evidence yet | | | | |
| AT-36 | M1 | A late settlement arrives after the migration cutover | no evidence yet | | | | |
| AT-37 | M1 | A Maharashtra pack has the general-body interest set to 18 percent | passed | no | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-37.json](AT-37.json) |
| AT-38 | M2 | A 300-member Maharashtra society has 20 verified attendees | no evidence yet | | | | |
| AT-39 | M1 | A 6,200 rupee NEFT credit lands in a unit's virtual account | no evidence yet | | | | |
| AT-40 | M1 | No device acknowledges an approval request for 10 seconds | no evidence yet | | | | |
| AT-41 | M3 | A tanker is invoiced for 12,000 L but the calibrated inlet shows 10,800 L | no evidence yet | | | | |
| AT-42 | M2 | A 7,800 rupee monthly member contribution under a GST-registered RWA pack | no evidence yet | | | | |
| AT-43 | M2 | TDS fixture with one contractor payment in March 2026 and one in April 2026 | no evidence yet | | | | |
| AT-44 | M1 | An owner confirms a tenant through a link and the committee then places a hold | no evidence yet | | | | |
| AT-45 | M1 | The journal hash chain is altered in a test database | no evidence yet | | | | |
| AT-46 | M1 | A 3,000 rupee UPI payment settles net of the 0.4 percent MDR | passed | no | 23071f327c | 2026-10-06T02:48:08+00:00 | [AT-46.json](AT-46.json) |
| AT-47 | M1 | An essential amenity is configured with a defaulter restriction | no evidence yet | | | | |
| AT-48 | M1 | A new guard picks Marathi at login and runs the five training scenarios | no evidence yet | | | | |
