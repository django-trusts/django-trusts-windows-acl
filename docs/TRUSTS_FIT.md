# Where Trusts fits in this repository

This note records what django-trusts and django-trusts-ordered-fold
do for the Windows ACL evaluator. It is not a claim that the
declarative authorization thesis is complete, and it is not a complete
Windows AccessCheck replacement.

Inspected for this revision:

| Tree | Commit | What it is |
| --- | --- | --- |
| `django-trusts` | `6934894489d4fc0e46de88b55b9a27f5f2eb2b41` | Core C1. Relationship-family Core; fold names are shims until C2. Constraint `django-trusts>=1.0.0.dev3,<2`. |
| `django-trusts-ordered-fold` | `c8c649aa5278db2b11fc380fa1646ae73df471ac` | P2 engine + `TrustsOrderedFoldModelBackend`. Reviewed head `639d4503f950931fee8bb900942bb1e599ae9b68`. |
| This repository | live history `1a9dc9c2b299dd15ee3aa5dcf083168050606d13` | Preserved V1–V43 evaluator baseline before this cutover. |

## Trusts fits naturally

- Consumer-owned `OrderedFoldImplementationConfig`
  (`winfs.apps.WinfsConfig`) with exact backend path
  `winfs.backends.WinfsBackend`.
- `WinfsBackend(TrustsOrderedFoldModelBackend)` is the sole configured
  Trusts path. Do not also list the generic OrderedFold backend.
- `register_ordered_fold(backend, WinAce, OrderedFold(...))` on the
  extension-owned handle: ordered remaining-bits over `WinAce`,
  FlatToken via `WinPrincipal` / `WinSidMember`, 32-bit `ACCESS_MASK`
  domain. Public `content` is `WinNode`. `descriptor` is
  content-relative (`security_descriptor`); `source_descriptor` is
  source-relative (`descriptor`). The two paths converge on the stored
  security descriptor.
- `Along(Ref(WinNode).parent, bound=64)` names the parent-link cap used
  by the consumer ancestor CTE. It is **not**
  `register_relationship(..., along=)`. This path does not register a
  relationship plan. Along SQL is SQLite-only, and ACE inheritance
  flags are not grant-on-ancestor reachability.
- Core `trusts` and `trusts_ordered_fold` are absent from
  `INSTALLED_APPS`. `manage.py check` stays clean of `trusts.E001` /
  `trusts.E002` / `trusts_ordered_fold.E001`. This project does not set
  `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`.

Owner authority remains an independent relational contribution
(`owner_sid ∈ requester token → RC|WD`) before the ACE scan.

## What this repository does not use

The evaluator path does **not** consult:

- `Trust`, Trustee adapter, `Content`, `Junction`, `TrustGroup`, `Role`
- Django `Group`
- `trusts.context.Context` or `trusts.trustee.Trustee`
- Transitional `KernelConfig` / core `AppConfig` / `TrustModelBackend`
- Application-facing `.registry.register_strategy(...)`, public `Ref`
  construction on the OrderedFold declaration, Core
  `BackendHandle.register_ordered_fold`, or the temporary
  `backend.register(..., strategy=...)` forwarder
- Core `trusts.query.AuthorizedManager` (relationship-family only after C1)
- A second `AUTHENTICATION_BACKENDS` OrderedFold path
- Pre-#187 same-path XOR workarounds or a mixed relationship/fold plan

## Application code that remains

- **Schema.** `WinSid`, principal / local-group membership, security
  descriptors, ordered ACEs, volumes, recursive nodes, optional streams.
- **Evaluator.** One PostgreSQL statement for remaining-bits AccessCheck
  and pre-pagination authorized listing. Inheritance is computed at read
  time. Invalid / unknown / NULL / negative / >32-bit ACE rows fail
  closed before applicability. Zero masks are legal.
- **Fixtures / seed / browser.** Documentation-derived V1–V43 matrix,
  `seed_winfs`, and a minimal authorized-object file browser.

See [WINFS_ACL.md](WINFS_ACL.md) and [migrates.md](../migrates.md).
