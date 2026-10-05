"""Single entry point registered with ``-p tests._harness.plugin`` (root pyproject addopts).

Importable from any test directory because the repo root is on `pythonpath`; this module only
wires the two sub-plugins so nothing else needs a conftest:

* ``pgfixtures``: `pg_server`, `template_db`, `db`, `bare_template_db`, `bare_db`, `DbHandle`
* ``evidence``:  markers (req/at/milestone/simulation/slow) validation, `--evidence`,
  `--milestone`, `--run-json`, evidence files + INDEX.md + _run.json
"""

pytest_plugins = ("tests._harness.pgfixtures", "tests._harness.evidence")
