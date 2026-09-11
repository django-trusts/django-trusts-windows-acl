# django-trusts-windows-acl

This project is a bounded demonstration that useful Windows-style ACL
behavior can be implemented on top of django-trusts. It is not a
replacement for Windows AccessCheck and does not claim complete DACL,
SACL, privilege, conditional-ACE, or platform compatibility. The
supported behavior matrix and explicit exclusions define the claim.

django-trusts compiles two evaluation strategies into one
`Allowed(user, content, permission)` relation: the default AnyPath
`EXISTS`, and a closed ordered remaining-bits fold. This consumer
registers the ordered strategy over explicit DACLs. Ancestor
inheritance, OI/CI/NP/IO, `CREATOR_OWNER`, `OWNER_RIGHTS`, owner
pre-grants, and cycle/depth failure remain on the preserved PostgreSQL
evaluator at merge `b8fff12` until Along has a PostgreSQL renderer.

Requires **Python 3.12+**, **Django 6.1**, and **PostgreSQL 14+**.
Core `'trusts'` must not appear in `INSTALLED_APPS`.

## Install

Core 1.x is unpublished. From sibling checkouts (or replace the core
path with a locally built sdist/wheel):

```
python -m pip install "Django>=6.1,<6.2"
python -m pip install ../django-trusts
python -m pip install .
```

Package metadata requires `django-trusts>=1.0.0.dev3,<2`. See
[migrates.md](migrates.md).

```
export DATABASE_URL=postgres://winfs:winfs@127.0.0.1:5432/winfs
python manage.py migrate
python manage.py seed_winfs
python manage.py runserver
```

A locally created role needs permission to
`SET session_replication_role` so V36 / V40 / V43 can insert rows that
writers refuse.

Open http://127.0.0.1:8000/winfs/ and log in. Seeded passwords are `demo`.

| User | What the seed is for |
| --- | --- |
| `alice` | `eng` member; reads `vol/` and `proj/` via group allow |
| `bob` | `eng` member; same group allow as alice |
| `carol` | no `eng` membership; AccessCheck denies the seeded tree |
| `admin` | volume-root owner (owner pre-grant is RC\|WD, not full control) |

## Configure

```python
INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'winfs.apps.WinfsConfig',
]
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'winfs.backends.WinfsAuthorizationBackend',
]
```

`WinfsConfig.ready()` registers `OrderedFold` on the owner registry.
The browser and V1–V43 matrix still call `access_check` /
`authorized_nodes` (one PostgreSQL statement, filter before pagination).

## Checks

```
python manage.py check
python manage.py test winfs
```

CI runs that suite against **PostgreSQL 16**.
