# django-trusts-windows-acl

django-trusts-windows-acl is a bounded relational implementation of Windows filesystem DACL semantics for Django. It models SIDs, local groups, security descriptors, ownership, ordered allow/deny ACEs, and inherited permissions, with object checks and authorized listings evaluated in fixed SQL queries.

The project validates the reusable Context contract from django-trusts while keeping Windows-specific policy data and evaluation independent of its convenience models. It is a reference implementation—not a complete replacement for Windows AccessCheck—and explicitly fails closed for unsupported Windows security features.

This is the implementation repository for the Windows ACL validation on
[django-trusts#17](https://github.com/django-trusts/django-trusts/issues/17)
(`bounded-winfs-acl-r3`). django-trusts core is not modified.

It depends on
[django-trusts](https://github.com/django-trusts/django-trusts)
**1.0.0.dev0** at revision
[`bfd55e23a9c7706271e3560c0ee1804023f1e69f`](https://github.com/django-trusts/django-trusts/commit/bfd55e23a9c7706271e3560c0ee1804023f1e69f)
(kernel master after
[#53](https://github.com/django-trusts/django-trusts/pull/53);
`trusts.apps.KernelConfig`, `trusts.context` / `trusts.trustee`).
This consumer does not install `django-trusts-zero`.

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
show every child name”. `admin` owns `vol/` but cannot LIST it (owner
pre-grant is RC\|WD). `carol` can see the volume name and is 403 on
every node. See [docs/WINFS_BROWSER.md](docs/WINFS_BROWSER.md) and
[docs/WINFS_ACL.md](docs/WINFS_ACL.md).

## Checks

```bash
python manage.py check
python manage.py test winfs
```

`manage.py check` must stay clean of `trusts.E001` / `trusts.E002`
and of kernel `trusts.E006` / `E007` / `E008`. Checks register from
`KernelConfig.ready()`, not from an authentication backend. This
project does not set `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS` and
does not install Zero.

The suite covers the V1–V43 matrix, docs-vs-evaluator catalog replay,
pending host-oracle provenance, depths 63/64/65, V38′, cycles,
group ownership, query-count, inspected plans, and the `/winfs/`
browser limitations. Plans are written under
[docs/winfs-plans/](docs/winfs-plans/).

CI runs that suite against **PostgreSQL 16** and runs the Windows-host
oracle on `windows-latest` (artifact only; results are not
auto-committed).

## Portability

Schema, matrix, and evaluator semantics are database-neutral. PostgreSQL
14+ is the first reference implementation and the inspected-plan backend
(recursive CTE, deterministic ACE sequencing, integer bit ops,
fail-closed cycle/depth). This slice does not ship a second SQL dialect.

Catalog vectors remain **`microsoft-docs`** until a native capture is
promoted into
[`winfs/oracle/fixtures/windows_host_observed.json`](winfs/oracle/fixtures/windows_host_observed.json)
tagged **`windows-host-observed`**. Linux CI cannot run AccessCheck.
See [docs/windows-oracle.md](docs/windows-oracle.md).

## What Trusts is used for

Honest Context registration only:

```python
Context.register_direct(WinNode, scope_field="security_descriptor")
Context.register_related(WinStream, through="node")
```

No `Trust`, Trustee adapter, `Content`, `Junction`, `TrustGroup`,
`Role`, or Django `Group` is on the evaluator path. Login uses
`django.contrib.auth.backends.ModelBackend`. See
[docs/TRUSTS_FIT.md](docs/TRUSTS_FIT.md).

## Trusts dependency

`requirements.txt` / `pyproject.toml` install Trusts from the git SHA
above, not from a published PyPI 1.0. Package metadata on that revision
is `1.0.0.dev0`. Install `trusts.apps.KernelConfig`; do not use bare
`'trusts'`.
