"""Provenance split: docs catalog vs pending host fixture vs evaluator."""

import json

from django.test import SimpleTestCase

from winfs.fixtures import standard_tree
from winfs.oracle.apply import evaluate_vector
from winfs.oracle.catalog import CATALOG, VECTOR_IDS, catalog_document, get_vector
from winfs.oracle.compare import compare_docs_vs_evaluator, compare_host_vs_evaluator
from winfs.oracle.schema import (
    CATALOG_PATH,
    HOST_FIXTURE_PATH,
    HOST_PROVENANCE,
    MS_DOCS_PROVENANCE,
    FixtureSchemaError,
    load_catalog_document,
    load_host_fixture,
    validate_host_fixture,
)

from .support import PostgresTestCase


class CatalogProvenanceTests(SimpleTestCase):
    def test_committed_catalog_matches_python_and_stays_docs_derived(self):
        on_disk = load_catalog_document()
        generated = catalog_document()
        self.assertEqual(on_disk, generated)
        self.assertEqual(on_disk["provenance"], MS_DOCS_PROVENANCE)
        self.assertEqual(VECTOR_IDS, tuple("V%s" % i for i in range(1, 44)))
        for row in on_disk["vectors"]:
            self.assertEqual(row["provenance"], MS_DOCS_PROVENANCE)
            self.assertNotEqual(row["provenance"], HOST_PROVENANCE)

    def test_committed_host_fixture_is_pending_and_empty(self):
        fixture = load_host_fixture()
        self.assertEqual(fixture["provenance"], HOST_PROVENANCE)
        self.assertEqual(fixture["status"], "pending-host-capture")
        self.assertIsNone(fixture["host"])
        self.assertEqual(fixture["results"], [])

    def test_host_fixture_rejects_docs_rows_relabeled_as_observed(self):
        fake = {
            "schema_version": 1,
            "provenance": HOST_PROVENANCE,
            "status": "captured",
            "host": {
                "computer": "example",
                "os": "Windows",
                "captured_at": "2026-01-01T00:00:00Z",
                "accesscheck_api": "advapi32.AccessCheck",
            },
            "results": [
                {
                    "id": "V3",
                    "provenance": MS_DOCS_PROVENANCE,
                    "status": "observed",
                    "allowed": True,
                    "desired_access": 1,
                }
            ],
        }
        with self.assertRaises(FixtureSchemaError):
            validate_host_fixture(fake)

    def test_host_fixture_rejects_invented_pending_results(self):
        fake = {
            "schema_version": 1,
            "provenance": HOST_PROVENANCE,
            "status": "pending-host-capture",
            "host": None,
            "results": [
                {
                    "id": "V3",
                    "provenance": HOST_PROVENANCE,
                    "status": "observed",
                    "allowed": True,
                    "desired_access": 1,
                }
            ],
        }
        with self.assertRaises(FixtureSchemaError):
            validate_host_fixture(fake)


class DocsVsEvaluatorTests(PostgresTestCase):
    def test_documentation_derived_catalog_matches_evaluator(self):
        decisions = {}
        for vector in CATALOG:
            data = standard_tree(volume_name="docs-%s" % vector.id)
            decisions[vector.id] = evaluate_vector(vector.id, data)
        rows = compare_docs_vs_evaluator(decisions)
        failed = [row for row in rows if not row.matched]
        self.assertEqual(
            failed,
            [],
            "docs-vs-evaluator mismatches: %s"
            % [
                (
                    row.vector_id,
                    row.evaluator_allowed,
                    row.evaluator_error,
                    row.expected_allowed,
                    row.expected_error,
                )
                for row in failed
            ],
        )


class HostVsEvaluatorTests(PostgresTestCase):
    def test_pending_host_fixture_compares_nothing(self):
        fixture = load_host_fixture()
        rows = compare_host_vs_evaluator(fixture, {})
        self.assertEqual(rows, [])

    def test_harness_compares_in_memory_host_row_without_writing_fixture(self):
        # Synthetic payload exercises the harness only. It is not a
        # committed windows-host-observed outcome.
        data = standard_tree(volume_name="host-harness-v3")
        decision = evaluate_vector("V3", data)
        fixture = {
            "schema_version": 1,
            "provenance": HOST_PROVENANCE,
            "status": "captured",
            "host": {
                "computer": "harness",
                "os": "in-memory",
                "captured_at": "not-a-host",
                "accesscheck_api": "test",
            },
            "results": [
                {
                    "id": "V3",
                    "provenance": HOST_PROVENANCE,
                    "status": "observed",
                    "allowed": True,
                    "desired_access": 1,
                }
            ],
        }
        rows = compare_host_vs_evaluator(fixture, {"V3": decision})
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].matched)
        disk = json.loads(HOST_FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(disk["results"], [])

    def test_owner_rights_divergence_does_not_fail_harness(self):
        data = standard_tree(volume_name="host-harness-v40")
        decision = evaluate_vector("V40", data)
        self.assertFalse(decision.allowed)
        fixture = {
            "schema_version": 1,
            "provenance": HOST_PROVENANCE,
            "status": "captured",
            "host": {
                "computer": "harness",
                "os": "in-memory",
                "captured_at": "not-a-host",
                "accesscheck_api": "test",
            },
            "results": [
                {
                    "id": "V40",
                    "provenance": HOST_PROVENANCE,
                    "status": "observed",
                    "allowed": True,
                    "desired_access": 0x40000,
                }
            ],
        }
        rows = compare_host_vs_evaluator(fixture, {"V40": decision})
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].matched)
        self.assertIn("OWNER_RIGHTS", rows[0].note)

    def test_not_representable_host_row_is_rejected(self):
        fixture = {
            "schema_version": 1,
            "provenance": HOST_PROVENANCE,
            "status": "captured",
            "host": {
                "computer": "harness",
                "os": "in-memory",
                "captured_at": "not-a-host",
                "accesscheck_api": "test",
            },
            "results": [
                {
                    "id": "V36",
                    "provenance": HOST_PROVENANCE,
                    "status": "observed",
                    "allowed": False,
                    "desired_access": 1,
                }
            ],
        }
        with self.assertRaises(ValueError):
            compare_host_vs_evaluator(fixture, {"V36": get_vector("V36")})

    def test_catalog_json_is_the_committed_export(self):
        self.assertTrue(CATALOG_PATH.is_file())
        self.assertEqual(
            json.loads(CATALOG_PATH.read_text(encoding="utf-8")),
            catalog_document(),
        )
