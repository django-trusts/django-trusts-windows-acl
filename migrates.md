# Migration record — final core conversion (#3)

This consumer now pairs with `django-trusts>=1.0.0.dev3,<2` (merge
`1e19b5d464c067186aada58943c3ee67c44b2aa0`). Core is a library. Do not
list `'trusts'` in `INSTALLED_APPS`.

## 1. Settings and implementation ownership

| | Previous (PR #1 / `b8fff123`) | New |
| --- | --- | --- |
| `INSTALLED_APPS` | `'trusts'` + `winfs.apps.WinfsConfig` | `winfs.apps.WinfsConfig` only |
| `AUTHENTICATION_BACKENDS` | `trusts.backends.TrustModelBackend` | `django.contrib.auth.backends.ModelBackend` then `winfs.backends.WinfsBackend` |
| AppConfig | `django.apps.AppConfig` + `Context.register_*` | `TrustsImplementationConfig` + `trusts_backend_paths` |
| Package | git pin `a2ab5a1` (`1.0.0.dev0`) | `django-trusts>=1.0.0.dev3,<2` at `1e19b5d` |

Login is username/password on `ModelBackend`. Object authorization is
the configured mixin backend.

## 2. Registration API

| | Previous | New |
| --- | --- | --- |
| Node scope | `Context.register_direct(WinNode, scope_field='security_descriptor')` | `registry.register_strategy(OrderedFold(...))` on `WinNode` |
| Stream sidecar | `Context.register_related(WinStream, through='node')` | `access_check` still resolves `WinStream` to `WinNode`; no second content terminal |
| Parent bound | `MAX_PARENT_DEPTH = 64` in SQL | `Along(Ref(WinNode).parent, bound=64)` declares the same cap; not `register(along=)` |

Along is not an AnyPath `along=` on `WinNode`. AnyPath and OrderedFold
cannot share one content terminal, and the Along renderer is SQLite-only.
Windows ACE inheritance (OI/CI/NP/IO, `SE_DACL_PROTECTED`) is not
grant-on-ancestor reachability. The consumer ancestor CTE uses
`Along.bound`.

## 3. Evaluator methods

| Method | Previous | New |
| --- | --- | --- |
| `access_check(user, resource, desired_mask)` | One SQL statement; Context gate | Same signature and V1–V43 outcomes; gate is a live OrderedFold plan; invalid/NULL/negative/>32-bit ACE rows fail closed before applicability (`error=invalid_source`); zero masks stay legal |
| `authorized_pks` / `authorized_nodes` | One SQL statement; filter then `ORDER BY` / `LIMIT` | Unchanged signatures; same one-statement contract |
| `user.has_perm('winfs.<action>_winnode', node)` | Not used (backend installed only for checks) | Mapped through `access_check` only for the full `winfs` / `WinNode` identity. Wrong-app strings (`auth.read_winnode`) and same-codename Permission rows on another content type do not map. Domain actions: `read`, `write`, `execute`, `readwrite`, `list`, `readcontrol`, `writedac`. |
| `WinNode.objects.authorized(user, permission)` | Absent | `AuthorizedManager` is installed; listing proofs stay on `authorized_pks` / `authorized_nodes` so inheritance and owner pre-grant remain one statement |

Authorization errors still do not become grants.

## 4. Schema

| | Previous | New |
| --- | --- | --- |
| `WinPrincipal.user` | `null=True` | Required (`null=False`) so FlatToken `principal_user` is a non-null hop |
| `WinAce.access_mask` | `>= 0` (`win_ace_mask_nonneg`) | `0..0xFFFFFFFF` (`win_ace_mask_32bit`) |
| `WinAce.trustee` | Field name `trustee`, column `trustee_sid_id` | Field renamed `trustee_sid` so OrderedFold `attname` matches the column |
| `WinSidMember.group` / `member` | Custom `db_column` vs `attname` | Renamed `group_sid` / `member_sid` so FlatToken SQL uses the stored columns |

Migration `0003_final_core_token_and_mask`. Existing fixture principals
already have a user.

## 5. Removed / refused

- `trusts.context.Context` and `ContextNotRegistered`
- `trusts.trustee.Trustee`
- `trusts.backends.TrustModelBackend`
- `trusts.apps.KernelConfig` / listing `'trusts'`
- Transitional core tombstone / compatibility shim

An incompatible core raises `ImproperlyConfigured` from
`winfs.compat.require_final_core()` before the backend or AppConfig
loads.

## Migration-bot checklist

- [ ] Set the package constraint to `django-trusts>=1.0.0.dev3,<2` and
      install merge `1e19b5d` (or an equivalent 1.0.0.dev3 wheel).
- [ ] Remove `'trusts'` / `KernelConfig` from `INSTALLED_APPS`.
- [ ] Replace `TrustModelBackend` with `ModelBackend` plus
      `winfs.backends.WinfsBackend`.
- [ ] Subclass `TrustsImplementationConfig` and set
      `trusts_backend_paths = ('winfs.backends.WinfsBackend',)`.
- [ ] Replace `Context.register_direct` / `register_related` with
      `register_strategy(OrderedFold)` from `winfs.policy`.
- [ ] Do not add `register(..., along=Along(...))` on `WinNode`.
- [ ] Call `access_check` / `authorized_pks` / `authorized_nodes` for
      full Windows semantics (inheritance, owner RC\|WD, OWNER_RIGHTS,
      depth/cycle). Do not treat OrderedFold-only `.authorized()` as
      AccessCheck.
- [ ] Map `has_perm` only for the full `winfs` / `WinNode` identity.
      `auth.read_winnode` and a same-codename Permission on another
      content type must not invoke AccessCheck.
- [ ] Run `0003_final_core_token_and_mask`. Refuse NULL
      `WinPrincipal.user` and ACE masks outside `0..0xFFFFFFFF`.
- [ ] `manage.py check` must stay clean of `trusts.E001` / `E002`.
      PostgreSQL is required for OrderedFold evaluate (`trusts.E006`).
- [ ] Replay V1–V43, depths 63/64/65, fail-closed invalid source rows,
      and the one-query plan tests.
- [ ] Do not invent Windows-host oracle results. Catalog rows stay
      documentation-derived until a reviewed host capture exists.
