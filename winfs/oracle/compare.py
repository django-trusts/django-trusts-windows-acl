"""Compare PostgreSQL evaluator outcomes to docs catalog and host fixtures.

Docs-derived rows and host-observed rows are asserted on separate paths.
A missing host capture is not a failure and is never filled in here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .catalog import CATALOG, get_vector
from .schema import HOST_PROVENANCE, MS_DOCS_PROVENANCE


@dataclass(frozen=True)
class CompareRow:
    vector_id: str
    path: str
    evaluator_allowed: bool
    evaluator_error: str | None
    expected_allowed: bool | None
    expected_error: str | None
    matched: bool
    note: str = ""


def compare_docs_vs_evaluator(decisions):
    """``decisions`` maps vector id → ``AccessDecision``.

    Only catalog ``microsoft-docs`` expectations are used.
    """
    rows = []
    for vector in CATALOG:
        if vector.provenance != MS_DOCS_PROVENANCE:
            raise ValueError(
                "%s: catalog provenance was relabeled to %s"
                % (vector.id, vector.provenance)
            )
        decision = decisions[vector.id]
        expected = vector.docs_expected
        matched = (
            bool(decision.allowed) == expected.allowed
            and (decision.error or None) == expected.error
        )
        rows.append(
            CompareRow(
                vector_id=vector.id,
                path="docs-vs-evaluator",
                evaluator_allowed=bool(decision.allowed),
                evaluator_error=decision.error,
                expected_allowed=expected.allowed,
                expected_error=expected.error,
                matched=matched,
            )
        )
    return rows


def compare_host_vs_evaluator(host_fixture, decisions):
    """Compare captured host rows to evaluator decisions.

    Empty ``results`` yields no assertions (pending capture). Rows tagged
    anything other than ``windows-host-observed`` are rejected. Catalog
    ``expected-divergence`` rows record both sides and do not fail on
    mismatch. ``not-representable`` host rows are rejected.
    """
    if host_fixture.get("provenance") != HOST_PROVENANCE:
        raise ValueError("host fixture provenance must be %s" % HOST_PROVENANCE)
    rows = []
    for raw in host_fixture.get("results") or []:
        if raw.get("provenance") != HOST_PROVENANCE:
            raise ValueError(
                "%s: host result is not tagged %s" % (raw.get("id"), HOST_PROVENANCE)
            )
        if raw.get("status") != "observed":
            raise ValueError("%s: skipped/synthetic rows are not comparable" % raw.get("id"))
        vector = get_vector(raw["id"])
        if vector.host_oracle.compare == "not-representable":
            raise ValueError(
                "%s: catalog marks this vector not-representable; "
                "do not store a host-observed outcome" % vector.id
            )
        decision = decisions[vector.id]
        host_allowed = bool(raw["allowed"])
        matched = bool(decision.allowed) == host_allowed
        note = ""
        if vector.host_oracle.compare == "expected-divergence":
            note = vector.host_oracle.notes
            # Divergence is documented, not a harness failure.
            matched = True
        rows.append(
            CompareRow(
                vector_id=vector.id,
                path="host-vs-evaluator",
                evaluator_allowed=bool(decision.allowed),
                evaluator_error=decision.error,
                expected_allowed=host_allowed,
                expected_error=None,
                matched=matched,
                note=note,
            )
        )
    return rows
