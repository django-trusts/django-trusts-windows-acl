"""Fixture schema for the provenance split.

Two documents, never mixed:

* ``catalog.json`` — Microsoft-documented expectations (``microsoft-docs``).
* ``windows_host_observed.json`` — native AccessCheck captures only
  (``windows-host-observed``). Empty ``results`` means capture is still
  pending. Do not copy docs-derived allow/deny rows into this file.
"""

from __future__ import annotations

import json
from pathlib import Path

SCHEMA_VERSION = 1
MS_DOCS_PROVENANCE = "microsoft-docs"
HOST_PROVENANCE = "windows-host-observed"
HOST_STATUSES = frozenset({"pending-host-capture", "partial", "captured"})
HOST_COMPARE = frozenset({"must-match", "expected-divergence", "not-representable"})

PACKAGE_DIR = Path(__file__).resolve().parent
CATALOG_PATH = PACKAGE_DIR / "catalog.json"
HOST_FIXTURE_PATH = PACKAGE_DIR / "fixtures" / "windows_host_observed.json"


class FixtureSchemaError(ValueError):
    """A catalog or host fixture violates the provenance contract."""


def _require(cond, message):
    if not cond:
        raise FixtureSchemaError(message)


def validate_catalog_document(doc):
    """Validate the committed Microsoft-docs catalog."""
    _require(isinstance(doc, dict), "catalog must be an object")
    _require(doc.get("schema_version") == SCHEMA_VERSION, "catalog.schema_version must be 1")
    _require(
        doc.get("provenance") == MS_DOCS_PROVENANCE,
        "catalog.provenance must be %s (never %s)" % (MS_DOCS_PROVENANCE, HOST_PROVENANCE),
    )
    vectors = doc.get("vectors")
    _require(isinstance(vectors, list) and vectors, "catalog.vectors must be a non-empty list")
    seen = set()
    for row in vectors:
        _require(isinstance(row, dict), "each catalog vector must be an object")
        vid = row.get("id")
        _require(isinstance(vid, str) and vid, "vector.id is required")
        _require(vid not in seen, "duplicate catalog id %s" % vid)
        seen.add(vid)
        _require(
            row.get("provenance") == MS_DOCS_PROVENANCE,
            "%s: catalog rows stay %s; do not relabel as host-observed" % (vid, MS_DOCS_PROVENANCE),
        )
        expected = row.get("docs_expected")
        _require(isinstance(expected, dict), "%s: docs_expected is required" % vid)
        _require(
            isinstance(expected.get("allowed"), bool),
            "%s: docs_expected.allowed must be a bool" % vid,
        )
        err = expected.get("error")
        _require(err is None or isinstance(err, str), "%s: docs_expected.error must be null or string" % vid)
        host = row.get("host_oracle") or {}
        _require(isinstance(host, dict), "%s: host_oracle must be an object" % vid)
        _require(
            isinstance(host.get("representable"), bool),
            "%s: host_oracle.representable must be a bool" % vid,
        )
        compare = host.get("compare")
        _require(compare in HOST_COMPARE, "%s: host_oracle.compare is invalid" % vid)
        if not host["representable"]:
            _require(
                compare == "not-representable",
                "%s: non-representable rows must use compare=not-representable" % vid,
            )
        else:
            _require(
                compare in {"must-match", "expected-divergence"},
                "%s: representable rows cannot use not-representable" % vid,
            )
    return doc


def validate_host_fixture(doc):
    """Validate a host-observed fixture. Empty results are valid (pending)."""
    _require(isinstance(doc, dict), "host fixture must be an object")
    _require(doc.get("schema_version") == SCHEMA_VERSION, "host.schema_version must be 1")
    _require(
        doc.get("provenance") == HOST_PROVENANCE,
        "host.provenance must be %s" % HOST_PROVENANCE,
    )
    status = doc.get("status")
    _require(status in HOST_STATUSES, "host.status must be pending-host-capture, partial, or captured")
    results = doc.get("results")
    _require(isinstance(results, list), "host.results must be a list")
    host = doc.get("host")
    if results:
        _require(isinstance(host, dict), "captured results require a host metadata object")
        for key in ("computer", "os", "captured_at", "accesscheck_api"):
            _require(host.get(key), "host.%s is required when results are present" % key)
        _require(status in {"partial", "captured"}, "non-empty results cannot stay pending-host-capture")
    else:
        _require(
            status == "pending-host-capture",
            "empty results must keep status=pending-host-capture",
        )
        _require(host is None, "pending capture must not invent host metadata")

    seen = set()
    for row in results:
        _require(isinstance(row, dict), "each host result must be an object")
        vid = row.get("id")
        _require(isinstance(vid, str) and vid, "result.id is required")
        _require(vid not in seen, "duplicate host result id %s" % vid)
        seen.add(vid)
        _require(
            row.get("provenance") == HOST_PROVENANCE,
            "%s: host results must be tagged %s; never copy docs-derived rows" % (vid, HOST_PROVENANCE),
        )
        _require(row.get("status") == "observed", "%s: only status=observed rows are comparable" % vid)
        _require(isinstance(row.get("allowed"), bool), "%s: allowed must be a bool" % vid)
        _require(isinstance(row.get("desired_access"), int), "%s: desired_access must be an int" % vid)
    return doc


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_catalog_document(path=None):
    return validate_catalog_document(load_json(path or CATALOG_PATH))


def load_host_fixture(path=None):
    return validate_host_fixture(load_json(path or HOST_FIXTURE_PATH))
