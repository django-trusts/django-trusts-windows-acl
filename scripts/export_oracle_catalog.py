#!/usr/bin/env python3
"""Write winfs/oracle/catalog.json from the Python catalog (no Django)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from winfs.oracle.catalog import catalog_document  # noqa: E402
from winfs.oracle.schema import CATALOG_PATH, validate_catalog_document  # noqa: E402


def main():
    doc = validate_catalog_document(catalog_document())
    CATALOG_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote", CATALOG_PATH)


if __name__ == "__main__":
    main()
