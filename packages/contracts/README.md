# Contracts

Generated, never hand-edited. Produced from the running application code by `tools/export_openapi.py`:

| File | Source |
|---|---|
| `openapi/dwaar.v1.json` | `dwaar_api.main.create_app().openapi()` (every discovered module included) |
| `jsonschema/DomainEvent.schema.json` | `dwaar_common.events.DomainEvent` (PRD 12.4 event contract) |
| `jsonschema/EdgeEvent.schema.json` | `dwaar_common.events.EdgeEvent` (PRD 12.3 edge sync envelope) |
| `jsonschema/ErrorBody.schema.json` | `dwaar_api.core.errors.ErrorBody` (PRD 12.2 error body) |

```
python tools/export_openapi.py            # regenerate
python tools/export_openapi.py --check    # CI: fail when committed files are stale
```

Output is deterministic (sorted keys, 2-space indent, trailing newline, no timestamps), so diffs show real contract
changes only. Clients (admin web, resident mobile, guard app) generate their types from these files.
