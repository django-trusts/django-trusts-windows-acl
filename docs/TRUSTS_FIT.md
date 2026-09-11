# Where Trusts fits in this repository

This note records what django-trusts does for the Windows ACL evaluator
and what stays outside Trust conveniences. It is not a claim that the
declarative authorization thesis is complete.

Trust conveniences (`Trust`, Trustee, `Content`, `TrustGroup`, Role)
are exercised in
[django-trusts-example](https://github.com/django-trusts/django-trusts-example)
for [django-trusts#16](https://github.com/django-trusts/django-trusts/issues/16).
This repository is the Windows ACL validation for
[django-trusts#17](https://github.com/django-trusts/django-trusts/issues/17).
It does not close the parent
[django-trusts#11](https://github.com/django-trusts/django-trusts/issues/11)
tracker.

Inspected for this revision:

| Tree | Commit | What it is |
| --- | --- | --- |
| `django-trusts` master (PR #53 merge) | `bfd55e23a9c7706271e3560c0ee1804023f1e69f` | Installable 1.0.0.dev0 used here (`KernelConfig`, Context + Trustee registries). |
| `django-trusts-example` `cursor/winfs-acl-r3-d580` | `8ca7831a45d870e4cec208f350c769a35ab6886a` | Temporary host of the approved `bounded-winfs-acl-r3` slice before this port. |

## Trusts fits naturally

- Honest `Context.register_direct(WinNode, scope_field='security_descriptor')`
  so each node owns its security-descriptor row.
- Honest `Context.register_related(WinStream, through='node')` so a
  sidecar shares that node’s DACL — not the parent folder.
- `manage.py check` stays clean of `trusts.E001` / `trusts.E002` and
  kernel `trusts.E006` / `E007` / `E008`. Checks run because
  `trusts.apps.KernelConfig` is installed, not because of an
  authentication backend. This project does not set
  `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS` and does not install
  `django-trusts-zero`.

Context is the reusable contract. Authorization itself is a remaining-bits
AccessCheck evaluator over ordinary SID / DACL / `WinNode.parent` tables.

## What this repository does not use

The evaluator path does **not** consult:

- `Trust`, Trustee adapter, `Content`, `Junction`, `TrustGroup`, `Role`
- Django `Group`
- `user.has_perm` / Zero `TrustModelBackend` grant compilation.
  Ordinary login is Django `ModelBackend`. AccessCheck does not call
  `has_perm`.

Trustee at the pinned kernel revision is a grant-path `Exists` compiler.
It cannot express stored-order allow/deny, so it is not an honest adapter
for this DACL.

Owner authority is an independent relational contribution
(`owner_sid ∈ requester token → RC|WD`) and does not traverse `Trust`.

## Application code that remains

- **Schema.** `WinSid`, principal / local-group membership, security
  descriptors, ordered ACEs, volumes, recursive nodes, optional streams.
- **Evaluator.** One PostgreSQL statement for remaining-bits AccessCheck
  and pre-pagination authorized listing. Inheritance is computed at read
  time. Cycles and depth overflow fail closed.
- **Fixtures / seed / browser.** Documentation-derived V1–V43 matrix,
  `seed_winfs`, and a minimal authorized-object file browser.
- **Windows-host oracle.** PowerShell AccessCheck script, catalog
  schema, and a committed host fixture that stays empty until a real
  capture is promoted (`windows-host-observed`). See
  [windows-oracle.md](windows-oracle.md).

See [WINFS_ACL.md](WINFS_ACL.md) for schema, depth, and portability.
See [WINFS_BROWSER.md](WINFS_BROWSER.md) for `/winfs/` limitations.
See [migrates.md](../migrates.md) for the ModelBackend / KernelConfig
settings change (no evaluator method change).
