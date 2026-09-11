# Bounded Windows filesystem ACL (django-trusts#17)

Revision **`bounded-winfs-acl-r3`** plus the approved depth erratum,
converted to final django-trusts core (`1.0.0.dev3`, merge `1e19b5d`).
Implementation lives in this repository. django-trusts core is unchanged.

Vectors in `winfs.tests.test_matrix` are **documentation-derived** from
Microsoft AccessCheck / ACE inheritance / MS-DTYP sources cited on
[issue #17](https://github.com/django-trusts/django-trusts/issues/17).
They are not bit-identical NTFS dumps. This PR does not invent
Windows-host oracle results. Observed host captures, if added later,
must stay tagged separately from `microsoft-docs` expectations.

## What this proves

Final core primitives can express the bounded Windows model without
weakening the fixed-query or fail-closed guarantees:

- `OrderedFold` evaluates stored-order allow/deny remaining-bits on
  `WinAce` (not deny-wins).
- `Along(Ref(WinNode).parent, bound=64)` is the typed parent-link cap.
  Live inheritance still uses the consumer CTE: Along is not registered
  as AnyPath grant-reachability on PostgreSQL.
- Object decision, authorized listing, and enumerate-then-paginate each
  remain one PostgreSQL statement.

Owner authority:

```text
owner_sid ∈ requester token  →  pre-grant READ_CONTROL | WRITE_DAC
```

It is not an all-permissions shortcut. `OWNER_RIGHTS` (`S-1-3-4`) on the
incoming ACE bag is DENY+error.

## Schema

Unique string columns (`WinSid.sid_string`, volume/group/node names) are
bounded `VARCHAR(255)`, not `TEXT`. `WinPrincipal.user` is required
(FlatToken). `WinAce.access_mask` is a 32-bit `ACCESS_MASK` (`0` through
`0xFFFFFFFF`). Zero masks are legal; negative and wider values fail
closed.

`WinSid` is the relational identity. `WinPrincipal` and `WinLocalGroup`
are typed profiles. `WinSidMember.group` is a real FK to
`win_local_group`. `WinSecurityDescriptor` holds `owner_sid` and
`SE_DACL_PROTECTED`. Ordered `WinAce` rows are the DACL.
`WinVolume` plus recursive `WinNode.parent` is the resource tree.
Optional `WinStream` shares the node’s descriptor via `access_check`,
not the parent folder.

## Depth (approved erratum)

```text
MAX_PARENT_DEPTH = Along.bound = 64 parent links
target dist = 0
valid root may appear at dist = 64
expand while current dist < 64
overflow iff dist = 64 AND parent_id IS NOT NULL
```

ACE count is **not** capped at 64. `MAX_ACE_SCAN = 4096` is a separate
operational incoming-ACE limit.

## Evaluation

One PostgreSQL statement implements both a single-object decision and
pre-pagination authorized listing (filter, then `ORDER BY` / `LIMIT`).
Algorithm: remaining-bits AccessCheck (MS-DTYP), **not** deny-wins.
Inheritance is computed at read time (OI / CI / NP / IO). Invalid,
unknown, NULL, or negative source rows fail closed before applicability.

## Setup

```bash
python -m pip install -r requirements.txt
DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/DB \
  python manage.py migrate
DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/DB \
  python manage.py seed_winfs
DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/DB \
  python manage.py test winfs
```

Browse `/winfs/` after logging in as a seeded user (password `demo`).
The browser uses authorized-object listing, not “LIST on the folder ⇒
show every child name”.

Inspected plans for shallow, depth-8, 1 000-sibling / two-group, and
protected-midtree cases are written under
[winfs-plans/](winfs-plans/) by the plan tests.
