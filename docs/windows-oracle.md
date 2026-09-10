# Windows-host oracle and provenance split

This repository keeps **two** sources of expected AccessCheck outcomes.
They are never relabeled into each other.

| Document | Provenance tag | What it is |
| --- | --- | --- |
| [`winfs/oracle/catalog.json`](../winfs/oracle/catalog.json) | `microsoft-docs` | V1–V43 expectations from Microsoft AccessCheck / ACE inheritance / MS-DTYP sources cited on [django-trusts#17](https://github.com/django-trusts/django-trusts/issues/17). Same outcomes as `winfs.tests.test_matrix`. |
| [`winfs/oracle/fixtures/windows_host_observed.json`](../winfs/oracle/fixtures/windows_host_observed.json) | `windows-host-observed` | Native `advapi32.AccessCheck` captures from a Windows NTFS host. Empty `results` means capture has not been promoted yet. |

The PostgreSQL evaluator is compared to each source on a **separate path**:

* **docs-vs-evaluator** — every catalog row (`winfs.tests.test_oracle.DocsVsEvaluatorTests` and the named V1–V43 matrix).
* **host-vs-evaluator** — only `status=observed` rows in the host fixture. Pending capture compares nothing and does not invent outcomes.

Windows semantics are **not** moved into django-trusts. The kernel pin is Context registration only.

## What is verified vs pending

| Slice | Status |
| --- | --- |
| V1–V43 vs Microsoft-documented remaining-bits AccessCheck | Verified against the PostgreSQL evaluator (docs-vs-evaluator). |
| Native Windows-host AccessCheck for representable vectors | **Pending host capture** in the committed fixture. The runnable oracle is `scripts/windows-host-oracle.ps1`. CI job `Windows-host AccessCheck oracle` uploads an artifact; promote that file here only after review. |
| V2 missing descriptor, V36 cycle, V37 unregistered Context, V38 missing principal, depth 63/64/65, ACE-scan cap | Evaluator-local. Catalog marks `host_oracle.representable=false`. Do not store host-observed rows for these. |
| V40 / V43 `OWNER_RIGHTS` (S-1-3-4) | Host capture is allowed. Compare mode is **`expected-divergence`**: Windows substitutes OWNER_RIGHTS for implicit owner bits; this evaluator wholly rejects S-1-3-4 (`DENY+error`) by design. |

Representable families the oracle builds: ordered allow/deny, requested bits, users/groups, inheritance/propagation, protected inheritance, owner RC\|WD, listing (child read ≠ parent list).

## How to capture host results

On a Windows NTFS host (Administrator), from the repo root:

```powershell
pwsh -File scripts/windows-host-oracle.ps1 `
  -CatalogPath winfs/oracle/catalog.json `
  -OutputPath artifacts/windows_host_observed.json
```

The script creates temporary local users `winfs-alice` / `winfs-bob` / `winfs-carol` / `winfs-admin` and group `winfs-eng`, applies raw SDDL, calls `advapi32.AccessCheck`, then deletes the principals.

CI: `.github/workflows/ci.yml` job `windows-host-oracle` (`windows-latest`) writes the same JSON as an artifact named `windows-host-observed`.

To promote a capture into the tree:

1. Confirm every `results[]` row has `"provenance": "windows-host-observed"` and `"status": "observed"`.
2. Do **not** copy `docs_expected` from the catalog into `results`.
3. Replace [`winfs/oracle/fixtures/windows_host_observed.json`](../winfs/oracle/fixtures/windows_host_observed.json).
4. Set `status` to `partial` or `captured` and fill `host.computer` / `os` / `captured_at` / `accesscheck_api`.
5. Re-run `python manage.py test winfs.tests.test_oracle`.

Regenerate the docs catalog (does not touch host results):

```bash
python scripts/export_oracle_catalog.py
```

## Out of scope for this oracle

SACLs / auditing, conditional ACEs, privileges (`SeTakeOwnershipPrivilege`, `SeSecurityPrivilege`, …), NIST/NGAC, kernel changes, and any claim of complete Windows AccessCheck compatibility.
