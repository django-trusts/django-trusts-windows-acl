# Where Trusts fits in this repository

This note records what final django-trusts core does for the Windows ACL
evaluator. It is not a claim that the declarative authorization thesis
is complete, and it is not a complete Windows AccessCheck replacement.

Inspected for this revision:

| Tree | Commit | What it is |
| --- | --- | --- |
| `django-trusts` master | `1e19b5d464c067186aada58943c3ee67c44b2aa0` | `1.0.0.dev3` library cutover. Constraint `django-trusts>=1.0.0.dev3,<2`. |
| This repository | PR #1 merge `b8fff123e173928ab9775d2ce4072197192c7f13` | Preserved V1–V43 evaluator baseline. |

## Trusts fits naturally

- Consumer-owned `TrustsImplementationConfig` (`winfs.apps.WinfsConfig`)
  with exact backend path `winfs.backends.WinfsBackend`.
- `registry.register_strategy(OrderedFold)` on `WinNode`: ordered
  remaining-bits over `WinAce`, FlatToken via `WinPrincipal` /
  `WinSidMember`, 32-bit `ACCESS_MASK` domain.
- `Along(Ref(WinNode).parent, bound=64)` names the parent-link cap used
  by the consumer ancestor CTE. It is **not** `register(along=)`:
  AnyPath and OrderedFold cannot share one terminal, Along SQL is
  SQLite-only, and ACE inheritance flags are not grant-on-ancestor
  reachability.
- Core `trusts` is absent from `INSTALLED_APPS`. `manage.py check` stays
  clean of `trusts.E001` / `trusts.E002`. This project does not set
  `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`.

Owner authority remains an independent relational contribution
(`owner_sid ∈ requester token → RC|WD`) before the ACE scan.

## What this repository does not use

The evaluator path does **not** consult:

- `Trust`, Trustee adapter, `Content`, `Junction`, `TrustGroup`, `Role`
- Django `Group`
- `trusts.context.Context` or `trusts.trustee.Trustee`
- Transitional `KernelConfig` / core `AppConfig` / `TrustModelBackend`

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
