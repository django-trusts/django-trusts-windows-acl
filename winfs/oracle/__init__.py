"""Windows-host oracle catalog, fixture schema, and comparison helpers.

Catalog rows are Microsoft-documentation-derived. Host-observed outcomes
live only in fixtures tagged ``windows-host-observed``. This package does
not invent host results and does not move Windows semantics into
django-trusts.
"""

from .catalog import CATALOG, VECTOR_IDS, get_vector
from .compare import compare_docs_vs_evaluator, compare_host_vs_evaluator
from .schema import (
    HOST_PROVENANCE,
    MS_DOCS_PROVENANCE,
    load_host_fixture,
    validate_catalog_document,
    validate_host_fixture,
)

__all__ = [
    "CATALOG",
    "HOST_PROVENANCE",
    "MS_DOCS_PROVENANCE",
    "VECTOR_IDS",
    "compare_docs_vs_evaluator",
    "compare_host_vs_evaluator",
    "get_vector",
    "load_host_fixture",
    "validate_catalog_document",
    "validate_host_fixture",
]
