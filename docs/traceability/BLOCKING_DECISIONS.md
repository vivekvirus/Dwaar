# Blocking decisions and external dependencies

Generated from `requirements.yaml` (Decision Register D-01..D-28, Open Questions Q1..Q14, [LEGAL]/[CA]/[VERIFY]/[TBD] labels) and `module_map.yaml` (external dependency catalogue). Regenerate by re-running the analysis if those files change. Source: Dwaar Master PRD v2.0 sections 3, 19.6 and 20.

## 1. Decisions that genuinely block safe M0/M1 implementation

**None.** Every decision in the register carries a default in the PRD, and every open question gates a *claim, approval or live enablement*, not the code. Building proceeds on the defaults below; each one is configuration that can change without a code change.

Defaults the build relies on (all taken from the PRD register; owner approval can still change them):

- D-01: Product name is the placeholder Dwaar pending trademark check (default: Dwaar placeholder; alternative Aangan with trademark check; approver: Owner)
- D-02: Pilot in Pune housing co-operatives under Maharashtra law (default: Pune, Maharashtra co-operative housing societies; Bengaluru after a Karnataka pack; approver: Owner + local advocate)
- D-04: Launch languages English, Hindi, Marathi; Kannada next; others once evaluated (default: English, Hindi, Marathi at M1; Kannada at M2; never claim all-language accuracy; approver: Owner)
- D-05: Resident app in React Native Expo with TypeScript plus accessible web (default: React Native Expo, TypeScript, iOS and Android plus accessible web; approver: Tech lead)
- D-06: Guard app is native Android Kotlin with Room and kiosk mode (default: Native Android Kotlin, Room/SQLite, device-owner kiosk; React Native only if kiosk and scanner tests pass; approver: Tech lead)
- D-07: Admin console built with Next.js, TypeScript, Tailwind and shadcn/ui (default: Next.js App Router, TypeScript, Tailwind, shadcn/ui; approver: Tech lead)
- D-08: Modular FastAPI monolith plus workers as the backend (default: Python FastAPI modular monolith with workers; split only for proven scale or isolation; approver: Tech lead)
- D-09: Managed multi-zone Postgres in India with RLS layered on top (default: Managed Postgres India region multi-zone, Supabase ap-south-1 by default, RLS as defence in depth; approver: Tech lead)
- D-10: Identifiers are time-ordered UUIDv7 using the native uuid type (default: UUIDv7; approver: Tech lead)
- D-11: Application event protocol for offline sync; no shared-file SQLite or money CRDTs (default: application event protocol; PowerSync only for resident and technician apps after a spike; approver: Tech lead)
- D-12: Edge gateway is Python on encrypted SQLite (WAL, synchronous FULL) with hardware keys (default: Python edge service, encrypted SQLite WAL synchronous=FULL, Linux mini-PC with hardware-backed keys; approver: Tech lead + installer)
- D-13: Offline validity: resident credentials 72 h, guest passes 2 h gate-bound (default: resident credentials 72 h; guest passes max 2 h gate-bound; supervisor overrides end at shift end; approver: Security supervisor)
- D-14: Approval requests expire after 90 seconds and are never auto-allowed (default: 90 seconds; never auto-allow; approver: Owner)
- D-15: Notification cascade defaults at 0, 10, 20, 35 and 90 seconds (default: push t=0, alternate adult t=10 s, masked IVR t=20 s, WhatsApp/SMS link t=35 s, expiry t=90 s; all configurable within limits; approver: Owner)
- D-17: Encrypted 35-day backup rotation; restores replay deletion tombstones (default: 35-day encrypted rotation; restores re-apply deletion tombstones; approver: Security lead)
- D-18: Provider-neutral AI adapter; default Claude models, Opus only where Sonnet fails (default: provider-neutral adapter; Claude Sonnet 5.5 and Haiku 4.5 by default; Opus 5.5 only where Sonnet fails evaluation; terms must be approved; approver: Privacy owner)

If a default is overturned later, the cost is rework in the named module, not a safety issue. The only items needing a human before *real-world* use are listed in section 2.

## 2. Open questions and labelled items: not blocking, handled as configuration

| ID | Label | Topic | Owner and evidence | Build treatment (M0/M1) |
|---|---|---|---|---|
| D-16 | LEGAL | Visitor data visible 30 days, extendable to 90, plus restricted legal archive | default: 30 days operational (to 90 with recorded justification) plus restricted archive of at least one year; approver: Counsel + society | Retention periods live in a versioned retention pack, shipped unapproved; defaults 30/90 days plus restricted archive. |
| D-21 | TBD | Indian cloud telephony, DLT SMS, WhatsApp utility templates and video provider | default: Indian cloud telephony, DLT SMS, WhatsApp utility templates, video provider; vendors undecided; approver: Owner | Provider adapters plus labelled simulators; vendors undecided, live channels disabled. |
| D-24 | LEGAL | Binding governance stays disabled until the legal pack is approved | default: disabled until the society legal pack is approved; opinion polls available; approver: Counsel | Binding governance flag off until a legal pack is approved; opinion polls only. |
| D-25 | LEGAL | Amenity restrictions for defaulters off by default, non-essential only, appealable | default: disabled by default; non-essential only with uploaded legal basis, notice and appeal; approver: Counsel | Defaulter amenity restriction flag off; essential services never restricted (INV-08). |
| D-28 | VERIFY | MDR and gateway charges borne by the society, never added for residents | default: society absorbs MDR and gateway fees; no surcharge to residents; fees shown in cost report; approver: Treasurer | Cost configuration marked VERIFY and shown as unconfirmed; no resident surcharge. |
| Q1 | - | Price acceptance at the 25, 35 and 50 rupee tiers | owner: Owner; evidence: 20 current contracts and 5 signed paid pilots | Commercial validation; no code impact. |
| Q2 | - | Push reliability on Xiaomi, Oppo, Vivo, Samsung and iOS handsets | owner: Tech lead; evidence: device matrix with blocked-permission tests | Push reliability measured on a device matrix; push adapter simulated until then. |
| Q3 | - | Exact gate hardware controller manuals, firmware and read-zone measurements | owner: Installer; evidence: controller manuals, firmware, read-zone measurements | Hardware manuals and measurements pending; simulator only, no performance claim. |
| Q4 | LEGAL | Scope of one-year Rule 8(3) retention for visitor photos and ANPR images | owner: Advocate; evidence: counsel opinion | Retention for visitor photos and ANPR images is configuration, unapproved by default. |
| Q5 | VERIFY | Maharashtra Rules 2026 values against Gazette text and model bye-laws status | owner: Advocate; evidence: Gazette text and Registrar circulars | Maharashtra pack values ship unapproved; no value hard-coded (INV-10). |
| Q6 | LEGAL | Karnataka Apartment Bill 2026 enactment status and final provisions | owner: Advocate; evidence: Assembly record | Karnataka pack not built before enactment is confirmed; M2 concern. |
| Q7 | LEGAL | Haryana position on online meetings and weighted votes | owner: Advocate; evidence: declaration and bye-laws | Haryana pack not built; M2+ concern. |
| Q8 | CA | GST classification of maintenance, amenities, EV recovery and TDS categories | owner: CA; evidence: CA review of entity and invoice types | GST/TDS/fund treatment ships as unapproved configuration pending CA review. |
| Q9 | VERIFY | UPI MDR classification, AutoPay and virtual-account costs from written acquirer schedule | owner: Treasurer; evidence: written acquirer schedule | Channel cost configuration marked VERIFY; no cost claims. |
| Q10 | - | Delivery partner access needs written approval and production API rights | owner: Owner; evidence: written partner approval and production API rights | Delivery partner access is M3; disabled. |
| Q11 | LEGAL | Whether water can be billed by meter in Maharashtra societies | owner: Advocate; evidence: counsel opinion | Water billing by meter disabled until counsel opinion (M3 module). |
| Q12 | TBD | Vendor terms still open for calls, SMS, WhatsApp and video | owner: Owner; evidence: commercial terms | Same as D-21; simulators only. |
| Q13 | - | AI provider processing terms on region, retention and no-training | owner: Privacy owner; evidence: signed terms | AI runs only on the labelled simulator provider until terms are signed. |
| Q14 | TBD | Name choice and trademark availability for the product | owner: Owner; evidence: trademark search | Placeholder name Dwaar used internally; rename is a string change. |

## 3. External dependencies: configuration, disabled by default, or labelled simulator

Every item below ships **disabled by default** or behind an adapter with a simulator labelled `simulation=true` that cannot reach real providers or hardware. Requirements that depend on them are `blocked-external` only when the adapter and simulator exist (computed by `tools/trace_check.py`); until then they show `not-started` or `partial`. Nothing here is claimed as working against a real provider, hardware unit or approver.

### Providers

- **provider:payment-aggregator**: RBI-authorised payment aggregator (default Razorpay): UPI, cards, netbanking, virtual accounts, direct settlement. Default state: disabled until credentials and onboarding exist; sandbox or labelled simulator (simulation=true) in local. Decisions: D-20, Q9. Affected requirements (6): PAY-01, PAY-03, PAY-04, PAY-07, PAY-11, D-20.
- **provider:bbpou**: BBPS operating unit for bill payment, only when commercially confirmed (M2). Default state: disabled; no simulator before M2. Decisions: D-20. Affected requirements (1): PAY-04.
- **provider:telephony-ivr**: Indian cloud telephony for IVR and masked proxy calls. Default state: disabled until vendor chosen; labelled simulator; intercom or office fallback stays visible. Decisions: D-21, Q12. Affected requirements (7): CALL-01, GATE-13, NOTIF-03, AI-D02, AI-R08, NOTIF-08, D-21.
- **provider:sms-dlt**: DLT-registered SMS headers and templates (also OTP delivery). Default state: disabled until DLT registration exists; labelled simulator. Decisions: D-21, Q12. Affected requirements (4): IAM-06, CALL-02, NOTIF-03, D-21.
- **provider:whatsapp**: WhatsApp utility templates. Default state: disabled until a vendor and templates are approved; labelled simulator. Decisions: D-21, Q12. Affected requirements (3): NOTIF-03, AMEN-03, D-21.
- **provider:push**: FCM and APNs push credentials. Default state: disabled until a Firebase and Apple project exist; labelled simulator. Decisions: none. Affected requirements (2): NOTIF-02, NOTIF-03.
- **provider:video**: Video provider for hybrid meetings (M2). Default state: disabled; M2 only. Decisions: D-21, Q12. Affected requirements (2): GOV-03, D-21.
- **provider:oidc-identity**: OIDC identity provider with phone OTP and MFA (default Supabase Auth). Default state: labelled simulator issuer when DWAAR_ENV=local; real provider via adapter. Decisions: D-09. Affected requirements (2): IAM-06, IAM-14.
- **provider:ai-model**: LLM, speech and OCR provider (default Anthropic Claude, self-hosted faster-whisper). Default state: deterministic labelled simulator provider; real provider disabled until terms are signed and evaluation passes. Decisions: D-18, D-19, Q13. Affected requirements (61): AI-C01, AI-C12, AI-F01, AI-G08, AI-R02, AI-R06, AI-R07, AI-SYS-01, AI-A01, AI-A03, AI-A04, AI-A05, AI-A06, AI-C02, AI-C03, AI-C04, AI-C06, AI-C07, AI-C08, AI-C09, AI-C10, AI-C11, AI-D02, AI-F02, AI-F03, AI-F05, AI-F06, AI-G01, AI-G03, AI-G04, AI-G06, AI-G07, AI-G09, AI-P01, AI-P02, AI-P03, AI-P04, AI-P05, AI-P06, AI-R01, AI-R03, AI-R04, AI-R05, AI-R08, AI-R09, AI-R10, AI-R11, ERP-04, ERP-07, FIN-11, GATE-10, NOTIF-08, PAR-06, PLAT-04, RPT-06, AI-I02, AI-I06, AI-G02, D-18, D-19, NFR-13.
- **provider:zoho-books**: Zoho Books API for accounting export (M2). Default state: disabled; Tally XML file export has no provider. Decisions: D-22. Affected requirements (2): EXP-02, D-22.
- **provider:gst-irp**: GST invoice registration portal, only where legally required (M3). Default state: disabled. Decisions: none. Affected requirements (1): TAX-03.
- **provider:android-enterprise**: Android Enterprise management for guard terminals. Default state: disabled; fleet functions stubbed behind an interface. Decisions: none. Affected requirements (1): PLAT-02.
- **provider:pentest-vendor**: Independent penetration test before paid general availability. Default state: external engagement; tracked as evidence. Decisions: none. Affected requirements (1): SEC-09.

### Hardwares

- **hardware:edge-gateway**: Certified fanless gateway with TPM, watchdog and UPS (field fsync, thermal, latency verification). Default state: software runs on any Linux host; no performance or durability claim until measured on the certified unit. Decisions: D-12, Q3. Affected requirements (9): EDGE-01, EDGE-08, EDGE-09, D-12, NFR-02, NFR-03, NFR-04, NFR-09, NFR-10.
- **hardware:barrier-controller**: One certified barrier controller model and revision, installer-commissioned. Default state: simulator implements the same adapter contract; live adapter disabled until installer sign-off. Decisions: D-23, Q3. Affected requirements (8): HW-06, HW-01, HW-02, HW-03, HW-04, HW-05, HW-07, D-23.
- **hardware:rfid-reader**: One UHF RFID reader model. Default state: simulator only until hardware is certified. Decisions: D-23. Affected requirements (3): VEH-02, VEH-04, D-23.
- **hardware:anpr-camera**: ANPR camera, illumination and compute (M3). Default state: disabled; labelled simulator for adapter tests. Decisions: none. Affected requirements (6): VEH-04, VEH-05, AI-G05, AI-S01, VEH-03, WATER-01.
- **hardware:meter-gateway**: LoRaWAN, Modbus or M-Bus meters, calibrated, with approved gateways (M3). Default state: disabled; replay simulator; no verified-volume label without calibration. Decisions: none. Affected requirements (5): IOT-01, IOT-02, IOT-03, WATER-01, WATER-03.
- **hardware:fuel-sensor-genset**: DG fuel sensors and genset controller (M3). Default state: disabled; replay simulator. Decisions: none. Affected requirements (2): FUEL-01, FUEL-02.
- **hardware:ocpp-charger**: Certified OCPP chargers and site meters (M3). Default state: disabled; simulator; engineered caps stay local. Decisions: none. Affected requirements (4): AI-I04, EV-01, EV-02, EV-03.
- **hardware:handheld-scanner**: USB or Bluetooth HID 2D scanner for sunlight use. Default state: keyboard-wedge input handled in software; field test on a real scanner pending. Decisions: none. Affected requirements (1): UX-10.

### Partners

- **partner:delivery-partner**: Delivery partner signed-token access (M3). Default state: disabled until a written partner contract and production API rights exist. Decisions: Q10. Affected requirements (1): PAR-07.

### Approvals

- **approval:legal-pack**: Counsel-approved legal pack per society and jurisdiction. Default state: pack ships unapproved; binding governance and statutory automation stay disabled. Decisions: D-24, Q5, Q6, Q7. Affected requirements (6): GOV-01, GOV-04, GOV-05, GOV-06, GOV-08, D-24.
- **approval:counsel**: Advocate confirmation of notices, retention, lawful basis and restrictions. Default state: configuration ships as unapproved defaults. Decisions: D-16, D-25, Q4. Affected requirements (10): PRIV-01, PRIV-02, PRIV-03, PRIV-05, PRIV-06, PRIV-07, AMEN-02, PRIV-10, D-25, SEC-06.
- **approval:ca**: Chartered accountant confirmation of fund, depreciation, GST and TDS treatment. Default state: tax and fund rules ship as unapproved configuration. Decisions: Q8. Affected requirements (5): ERP-01, ERP-06, TAX-02, TAX-04, TAX-03.
- **approval:acquirer**: Written acquirer schedule for UPI MDR classification and channel costs. Default state: cost configuration marked VERIFY and shown as unconfirmed. Decisions: D-28, Q9. Affected requirements (2): PAY-05, D-28.
- **approval:installer**: Qualified installer and society commissioning sign-off. Default state: live actuation stays disabled. Decisions: D-23. Affected requirements (1): HW-05.
- **approval:metrology**: Metrology review of tanker variance thresholds and calibration. Default state: threshold fixed at the proposal and flagged unreviewed. Decisions: none. Affected requirements (1): WATER-02.
- **approval:discom**: DISCOM, operator and tax approval for EV charging billing. Default state: EV billing disabled. Decisions: none. Affected requirements (1): EV-03.
- **approval:ai-provider-terms**: Signed AI provider terms: region, retention, no-training. Default state: real AI provider disabled; simulator only. Decisions: D-18, Q13. Affected requirements (5): AI-SYS-01, AI-SYS-02, PRIV-14, D-18, SEC-07.

### Data and field evidence

- **field:pilot-measurement**: Measurements taken on real devices, sites and traffic (INV-12). Default state: targets are tested with simulated load only; no SLO claim until measured in the field. Decisions: none. Affected requirements (3): NFR-01, NFR-05, NFR-06.
- **data:baseline-observation**: 60 to 90 days of baseline observation for data-dependent AI (PRD 11.4). Default state: transparent rules first; insufficient data is a valid output. Decisions: none. Affected requirements (9): AI-F04, AI-F07, AI-F08, AI-G10, AI-I01, AI-I03, AI-I05, AI-I07, AI-S02.
