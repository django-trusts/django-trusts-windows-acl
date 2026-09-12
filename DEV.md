# Internal development record

> **Warning:** This file preserves a transitional implementation record. It contains exact development revisions, internal phase names, and setup assumptions that may no longer describe the supported public package. Start with [README.md](README.md) for current user guidance.

## Archived pre-documentation README
# django-trusts-windows-acl

django-trusts-windows-acl is a bounded relational implementation of Windows filesystem DACL semantics for Django. It models SIDs, local groups, security descriptors, ownership, ordered allow/deny ACEs, and inherited permissions, with object checks and authorized listings evaluated in fixed SQL queries.

The project validates final django-trusts core (`OrderedFold`, `Along`,
`TrustsImplementationConfig`) while keeping Windows-specific policy data
and evaluation on this consumer. It is a reference implementation—not a
complete replacement for Windows AccessCheck—and explicitly fails closed
for unsupported Windows security features.

This is the implementation repository for the Windows ACL validation on
[django-trusts#17](https://github.com/django-trusts/django-trusts/issues/17)
(`bounded-winfs-acl-r3` on final core). django-trusts core is not modified.

It depends on
[django-trusts](https://github.com/django-trusts/django-trusts)
**`>=1.0.0.dev3,<2`** at revision
[`1e19b5d464c067186aada58943c3ee67c44b2aa0`](https://github.com/django-trusts/django-trusts/commit/1e19b5d464c067186aada58943c3ee67c44b2aa0).
Do not list `'trusts'` in `INSTALLED_APPS`.

Requires **Python ≥ 3.12** and **PostgreSQL 14+**.

## Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
createdb winfs   # or any PostgreSQL 14+ database
export DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/winfs
python manage.py migrate
python manage.py seed_winfs
python manage.py runserver
```

When `DATABASE_URL` is unset, settings default to
`postgres://winfs:winfs@127.0.0.1:5432/winfs`. The official PostgreSQL
image user (and CI) is a superuser. A locally created role needs
permission to `SET session_replication_role` so V36 / V40 / V43 can
bypass write triggers and insert OWNER_RIGHTS or cycle rows that
writers refuse (`ALTER USER winfs WITH SUPERUSER` is enough).

Open http://127.0.0.1:8000/winfs/ and log in. Seeded passwords are `demo`.

| User | What the seed is for |
| --- | --- |
| `alice` | `eng` member; reads `vol/` and `proj/` via group allow |
| `bob` | `eng` member; same group allow as alice |
| `carol` | no `eng` membership; AccessCheck denies the seeded tree |
| `admin` | volume-root owner (owner pre-grant is RC\|WD, not full control) |

The browser uses authorized-object listing, not “LIST on the folder ⇒
show every child name”. See [docs/WINFS_ACL.md](docs/WINFS_ACL.md).

## Checks

```bash
python manage.py check
python manage.py test winfs
```

`manage.py check` must stay clean of `trusts.E001` / `trusts.E002`.
This project does not set `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`.
PostgreSQL is required for OrderedFold evaluate.

The suite covers the V1–V43 matrix, depths 63/64/65, V38′, cycles,
group ownership, query-count, and inspected plans (shallow, depth-8,
1,000-sibling / two-group, protected mid-tree). Plans are written under
[docs/winfs-plans/](docs/winfs-plans/).

CI runs that suite against **PostgreSQL 16**.

## Portability

Schema, matrix, and evaluator semantics are database-neutral. PostgreSQL
14+ is the first reference implementation and the inspected-plan backend
(recursive CTE, deterministic ACE sequencing, integer bit ops,
fail-closed cycle/depth). This slice does not ship a second SQL dialect.

Vectors remain **documentation-derived** until separately verified
against a Windows host.

## What Trusts is used for

```python
registry.register_strategy(OrderedFold(...))  # WinNode remaining-bits
Along(Ref(WinNode).parent, bound=64)          # parent-link cap only
```

No `Trust`, Trustee, `Content`, `Junction`, `TrustGroup`, `Role`,
Django `Group`, or `Context` is on the evaluator path. See
[docs/TRUSTS_FIT.md](docs/TRUSTS_FIT.md) and [migrates.md](migrates.md).

## Trusts dependency

`requirements.txt` installs Trusts from the git SHA above. Package
metadata on that revision is `1.0.0.dev3`. The declared constraint is
`django-trusts>=1.0.0.dev3,<2`.
