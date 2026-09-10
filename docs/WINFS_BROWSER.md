# File-browser flow (`/winfs/`) and limitations

The browser is a thin authorized-object listing over the same PostgreSQL
AccessCheck statement used by the matrix. It is not Windows Explorer and
it is not a complete NTFS substitute.

After `python manage.py seed_winfs`, passwords are `demo`. Authentication
is Django `ModelBackend` (username/password only).

## Seeded walk

1. Open `/accounts/login/` (anonymous `/winfs/` redirects here).
2. Sign in as `alice`.
3. `/winfs/` lists volume names. Click `vol`.
4. Volume root `vol/` → `proj/` → `secret/` → `notes.txt`, or `proj/readme.txt`.
5. Each node shows AccessCheck decisions for `R`, `W`, `LIST`, `RC`, `WD`.
6. Folder children are `authorized_nodes(user, FILE_READ_DATA, parent_id=…)`.
7. Sign out; sign in as `carol`. Volume list still renders; entering `vol/` is 403.

| User | Seed intent | What `/winfs/` actually does |
| --- | --- | --- |
| `alice` | `eng` member | 200 on `vol/`, `proj/`, `secret/`, `notes.txt`, `readme.txt` via group allow (`vol` CI, `proj` OI\|CI). |
| `bob` | `eng` member | Same group allow as alice. |
| `carol` | not in `eng` | 200 on `/winfs/` (volume **names**). 403 on `vol/` and every seeded node. |
| `admin` | volume-root owner | 403 on `vol/`. Owner pre-grant is `READ_CONTROL \| WRITE_DAC`, not `FILE_LIST_DIRECTORY`. |

## Concrete limitations still encountered

**Authorized listing ≠ “LIST folder ⇒ all children.”**
Windows `FILE_LIST_DIRECTORY` on a folder reveals child *names* even when
the children deny `FILE_READ_DATA`. This browser lists only children the
requester can `FILE_READ_DATA` / `FILE_LIST_DIRECTORY` as objects. A user
who may LIST `proj/` and is denied read on `readme.txt` does not see that
name. That is the #17 permitted-object thesis, not Explorer.

**Volume list is not AccessCheck-filtered.**
`volume_list` returns every `WinVolume` row to any authenticated user.
Carol can see that `vol` exists without being able to open it.

**Owner is not full control.**
`admin` owns `vol/` and `proj/` and still cannot browse them after seed.
The checks table on a node the owner *can* open (for example alice on
`notes.txt`, which she owns) shows `RC`/`WD` allowed and `R`/`W` denied
until an ACE grants data bits.

**`OWNER_RIGHTS` (S-1-3-4) fail-closed.**
Any incoming ACE whose trustee is `S-1-3-4` — explicit or inherited —
makes the evaluator deny the object with `error=owner_rights` and
suppresses the owner pre-grant. The browser then returns 403 for LIST/R
as well, not a Windows-style substitution of OWNER_RIGHTS for implicit
owner bits. Writers refuse to store that ACE; tests insert it only by
bypassing triggers.

**Depth overflow and cycles fail closed.**
A parent chain of 65 links, or a `parent` cycle, denies with
`overflow` / `cycle`. The browser maps that deny to HTTP 403, not 503.
503 is only `WinfsBackendError` (non-PostgreSQL).

**Missing principal / unregistered resource.**
A logged-in Django user without `win_principal` is denied
(`missing_principal`). A non-`WinNode` / non-`WinStream` object is
`context_not_registered`. The browser only evaluates nodes.

**No privilege / SACL / conditional ACE path.**
The UI cannot express `SeTakeOwnershipPrivilege`, auditing, or
conditional ACEs. Unsupported Windows features stay fail-closed in SQL.

**Seed is documentation-derived.**
Group allows on `vol/` and `proj/` match the V1–V43 fixture tree, not a
bit-identical NTFS dump. Host-observed comparison is the oracle fixture,
not this seed.

## Evaluator contract the browser relies on

Individual `access_check` and `authorized_nodes` remain one fixed
PostgreSQL statement each, relational, fail-closed. See
[WINFS_ACL.md](WINFS_ACL.md). No API change in this slice
([migrates.md](../migrates.md)).
