# django-trusts-windows-acl

Relational, queryable Windows-style permissions for Django.

`django-trusts-windows-acl` is a bounded reference implementation of explicit, table-defined authorization on [django-trusts](https://github.com/django-trusts/django-trusts) 1.x. SIDs, local-group membership, security descriptors, ownership, and ordered allow/deny entries are ordinary Django rows. The same registered policy drives both one-object decisions and authorized listings, each in one PostgreSQL statement.

Use this project to study or build ACL-shaped authorization where permissions are stored as data and filtering must happen before pagination. It also includes a small file-browser demo.

> This is deliberately a supported subset, not a complete Windows ACL implementation or a replacement for Windows `AccessCheck`. The current validation vectors are derived from Microsoft documentation rather than captured from a Windows host.

## Quick start

From a source checkout:

```bash
git clone https://github.com/django-trusts/django-trusts-windows-acl.git
cd django-trusts-windows-acl
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
createdb winfs
export DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/winfs
python manage.py migrate
python manage.py seed_winfs
python manage.py runserver
```

Open <http://127.0.0.1:8000/winfs/> and sign in as `alice`, `bob`, `carol`, or `admin`; the seeded password is `demo`.

The package requires Python 3.12 or newer, Django 6.1, django-trusts 1.x, and PostgreSQL 14 or newer. CI runs on PostgreSQL 16.

## Configure Django

Add the implementation app and its object-permission backend:

```python
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "winfs.apps.WinfsConfig",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "winfs.backends.WinfsBackend",
]
```

`WinfsConfig` owns and registers the Windows policy. `django-trusts` is used as a Python library, so it is not a separate installed app. Django's `ModelBackend` continues to handle login and model-level permissions; `WinfsBackend` handles object permissions for `WinNode` and `WinStream`.

## Persist policy as data

The evaluator reads normal relational state:

- `WinSid` identifies users and local groups.
- `WinPrincipal` and `WinSidMember` build the requester's flat token.
- `WinSecurityDescriptor` stores ownership and DACL-protection state.
- ordered `WinAce` rows store trustee, allow/deny polarity, inheritance flags, and a 32-bit access mask.
- `WinNode.parent` forms the bounded resource tree; `WinStream` shares its node's DACL.

The implementation registers an `OrderedFold` strategy for `WinNode`. The actual consumer-owned registration is exposed through one tested function:

```python
from winfs.policy import register_winfs_policy

register_winfs_policy(registry)
```

The parent declaration is likewise explicit and bounded:

```python
from trusts.core import Along, Ref
from winfs.models import WinNode

INHERITANCE_WALK = Along(Ref(WinNode).parent, bound=64)
```

See [`winfs/policy.py`](winfs/policy.py) for the complete `OrderedFold`, permission-mask domain, and token declaration.

## Authorize objects and listings

Use the same policy for a single object, a filtered listing, or Django's familiar permission API:

```python
from winfs.constants import R
from winfs.evaluate import access_check, authorized_nodes

decision = access_check(request.user, node, R)
visible_children = authorized_nodes(
    request.user,
    R,
    parent_id=folder.pk,
    limit=25,
)
allowed = request.user.has_perm("winfs.read_winnode", node)
```

`access_check()` returns an `AccessDecision`. `authorized_nodes()` and `authorized_pks()` filter unauthorized rows before `ORDER BY`, `LIMIT`, and `OFFSET`; they do not enumerate objects in Python. Folder LIST permission allows the browser to enumerate children, but each child must still pass its own authorization check.

## Supported subset

- stored-order, remaining-bits allow/deny evaluation;
- object inheritance and container inheritance (`OI`, `CI`, `NP`, and `IO`), including protected DACLs;
- owner pre-grant of `READ_CONTROL | WRITE_DAC`, not full control;
- flat local-group membership;
- 32-bit access masks and request-side `GENERIC_*` mapping;
- one SQL statement for shallow, depth-8, protected-midtree, and authorized-listing cases;
- a maximum of 64 parent links and 4,096 incoming ACEs.

Malformed or unsupported policy fails closed. Missing principals or descriptors, cycles, dangling parents, depth or ACE overflow, invalid masks, unregistered resources, and unsupported `OWNER_RIGHTS` entries cannot become grants.

Not implemented: SACL/auditing, conditional ACEs, privileges, nested-group expansion, Windows `OWNER_RIGHTS` substitution, or a second SQL dialect. Real applications still need validation for their own policy-editing workflows and threat model.

## Project family and further reading

- [django-trusts](https://github.com/django-trusts/django-trusts): the declarative relational-authorization core.
- [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions): permissions implied by organization and team relationships.
- [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero): the concrete continuation and migration path for django-trusts 0.x.
- [Windows ACL model and proof notes](docs/WINFS_ACL.md)
- [How this consumer uses Trusts](docs/TRUSTS_FIT.md)
- [Development and historical record](DEV.md)
- [Migration notes](migrates.md)

## License

BSD 2-Clause. Copyright © 2026 BeeDesk, Inc.
