# django-trusts-windows-acl

django-trusts-windows-acl is a bounded relational implementation of Windows filesystem DACL semantics for Django. It models SIDs, local groups, security descriptors, ownership, ordered allow/deny ACEs, and inherited permissions, with object checks and authorized listings evaluated in fixed SQL queries.

The project validates the reusable Context contract from django-trusts while keeping Windows-specific policy data and evaluation independent of its convenience models. It is a reference implementation—not a complete replacement for Windows AccessCheck—and explicitly fails closed for unsupported Windows security features.

This is the implementation repository for the Windows ACL validation on
[django-trusts#17](https://github.com/django-trusts/django-trusts/issues/17)
(`bounded-winfs-acl-r3`). django-trusts core is not modified.

It depends on
[django-trusts](https://github.com/django-trusts/django-trusts)
**1.0.0.dev0** at revision
[`a2ab5a13752751ee761990bea778c9f868b2ad6e`](https://github.com/django-trusts/django-trusts/commit/a2ab5a13752751ee761990bea778c9f868b2ad6e)
(`trusts.context` / `trusts.trustee` after PRs
[#41](https://github.com/django-trusts/django-trusts/pull/41) and
[#42](https://github.com/django-trusts/django-trusts/pull/42)).

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

`manage.py check` must stay clean of `trusts.E001` / `trusts.E002`
(invalid `Expr` registrations or leftover callable conditions). This
project does not set `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`.

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

Honest Context registration only:

```python
Context.register_direct(WinNode, scope_field="security_descriptor")
Context.register_related(WinStream, through="node")
```

No `Trust`, Trustee adapter, `Content`, `Junction`, `TrustGroup`,
`Role`, or Django `Group` is on the evaluator path. See
[docs/TRUSTS_FIT.md](docs/TRUSTS_FIT.md).

## Trusts dependency

`requirements.txt` / `pyproject.toml` install Trusts from the git SHA
above, not from a published PyPI 1.0. Package metadata on that revision
is `1.0.0.dev0`.
