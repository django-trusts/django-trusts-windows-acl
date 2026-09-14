# Migration record — Windows cutover W (#11)

This consumer now pairs with:

- Core C1 squash `6934894489d4fc0e46de88b55b9a27f5f2eb2b41`
  (`django-trusts>=1.0.0.dev3,<2`)
- OrderedFold P2 squash `c8c649aa5278db2b11fc380fa1646ae73df471ac`
  (reviewed head `639d4503f950931fee8bb900942bb1e599ae9b68`;
  `django-trusts-ordered-fold>=1.0.0.dev0,<2`)

Core is a library. The OrderedFold package ships no Django app. Do not
list `'trusts'` or `'trusts_ordered_fold'` in `INSTALLED_APPS`.

## Backend topology

One configured Trusts path only. `TrustsOrderedFoldModelBackend` is
already the concrete Django `ModelBackend`. `WinfsBackend` subclasses
it once and keeps the AccessCheck `has_perm` intercept. Do not inherit
`ModelBackend` a second time and do not list the generic OrderedFold
backend as a second `AUTHENTICATION_BACKENDS` path.

```python
# Old (W-methods / 1a9dc9c)
from django.contrib.auth.backends import ModelBackend
from trusts.backends import TrustModelBackendMixin

class WinfsBackend(TrustModelBackendMixin, ModelBackend):
    ...

# New (W / this PR)
from trusts_ordered_fold.backends import TrustsOrderedFoldModelBackend

class WinfsBackend(TrustsOrderedFoldModelBackend):
    # retain the existing AccessCheck has_perm intercept
    ...
```

| | Previous (W-methods / `1a9dc9c`) | New (W / P2) |
| --- | --- | --- |
| Concrete backend | `TrustModelBackendMixin` + `ModelBackend` | `WinfsBackend(TrustsOrderedFoldModelBackend)` |
| Implementation owner | `TrustsImplementationConfig` | `OrderedFoldImplementationConfig` |
| Listed Trusts path | `winfs.backends.WinfsBackend` | unchanged; still the sole owned path |
| Generic OrderedFold path | n/a | do not list `trusts_ordered_fold.backends.TrustsOrderedFoldModelBackend` |
| Login | Django `ModelBackend` | unchanged |

`WinfsConfig` still owns `trusts_backend_paths = ('winfs.backends.WinfsBackend',)`.

## Import and registration

Import the five construction types and `register_ordered_fold` from
`trusts_ordered_fold`. Do not import Core fold-name shims
(`trusts.core.OrderedFold`, `PermissionMaskDomain`, `MaskEntry`,
`PolarityMap`, `FlatToken`) and do not call Core
`BackendHandle.register_ordered_fold`.

```python
# Old (W-methods / 1a9dc9c)
from trusts.core import FlatToken, OrderedFold
from trusts.core import MaskEntry, PermissionMaskDomain, PolarityMap
backend.register_ordered_fold(WinAce, NODE_FOLD)

# New (W / P2)
from trusts_ordered_fold import (
    FlatToken,
    MaskEntry,
    OrderedFold,
    OrderedFoldImplementationConfig,
    PermissionMaskDomain,
    PolarityMap,
    TrustsOrderedFoldModelBackend,
    register_ordered_fold,
)
register_ordered_fold(backend, WinAce, NODE_FOLD)
```

`register_winfs_policy(backend)` still takes the configured backend and
is idempotent on backend identity. It now donates through the
extension-owned function onto an `OrderedFoldBackendHandle` /
`OrderedFoldRegistry`. A Core `BackendHandle` / `TrustsRegistry` is
`TypeError`.

| | Previous (W-methods / `1a9dc9c`) | New (W / P2) |
| --- | --- | --- |
| Import root | `trusts.core` fold names | **`trusts_ordered_fold`** |
| Donation host | `backend.register_ordered_fold(WinAce, OrderedFold(...))` | `register_ordered_fold(backend, WinAce, OrderedFold(...))` |
| Handle / registry | Core `BackendHandle` + `TrustsRegistry` | `OrderedFoldBackendHandle` + `OrderedFoldRegistry` |
| Compat floor | Core fold names + `BackendHandle.register_ordered_fold` | OrderedFold package + `TrustsOrderedFoldModelBackend`; Core fold-name shims are not a floor |
| Vendor check | Core `trusts.E006` | `trusts_ordered_fold.E001` |
| Listing helper | Core `AuthorizedManager` (now relationship-only) | OrderedFold family-local `AuthorizedManager`, or retain `authorized_nodes` |
| Package pins | Core `f5211c11047eb6810680f5d1b13bf34b2c376635` | Core `6934894489d4fc0e46de88b55b9a27f5f2eb2b41` + P2 `c8c649aa5278db2b11fc380fa1646ae73df471ac` |

Public `content` remains `WinNode`. The two descriptor paths still
converge on the same stored security descriptor
(`WinAce.descriptor → SecurityDescriptor ← WinNode.security_descriptor`).
Do not derive one path from the other.

The consumer-owned 64-link parent-recursion bound stays
`INHERITANCE_WALK = Along(Ref(WinNode).parent, bound=64)`. Do not
reinterpret it as a relationship `along=` and do not register a
relationship on this path. Pre-#187 "AnyPath and OrderedFold cannot
share one terminal" wording described a Core XOR that this consumer
never used; Windows stays a single OrderedFold path.

`WinNode.objects.authorized` is the OrderedFold family-local manager.
It evaluates the registered fold only (explicit DACL remaining-bits).
Inheritance, owner pre-grant, OWNER_RIGHTS, and depth/cycle stay on
`access_check` / `authorized_pks` / `authorized_nodes`. Do not leave
Core `trusts.query.AuthorizedManager` on this fold-only model.

Registration, duplicate donation, and malformed-declaration checks
remain zero SQL and leave no partial mutation. Frozen / finalized
registries still raise before path parsing.

## W migration-bot checklist

Search application code, docs, tests, and packaging fixtures for:

```text
from trusts.core import OrderedFold
from trusts.core import PermissionMaskDomain
from trusts.core import MaskEntry
from trusts.core import PolarityMap
from trusts.core import FlatToken
from trusts.query import AuthorizedManager
TrustModelBackendMixin
backend.register_ordered_fold(
handle.register_ordered_fold(
.registry.register_strategy(
register_strategy(
trusts.E006
SILENCED_SYSTEM_CHECKS.*E006
AnyPath and OrderedFold cannot share one terminal
f5211c11047eb6810680f5d1b13bf34b2c376635
1e19b5d464c067186aada58943c3ee67c44b2aa0
6cf12d990c65e20dc862ed1dd1db8f8ec4f874be
register_winfs_policy(
from trusts_ordered_fold import
register_ordered_fold(
TrustsOrderedFoldModelBackend
OrderedFoldImplementationConfig
trusts_ordered_fold.E001
```

Then:

- [ ] Install Core C1 `6934894489d4fc0e46de88b55b9a27f5f2eb2b41`
      and OrderedFold P2 `c8c649aa5278db2b11fc380fa1646ae73df471ac`.
- [ ] Change `WinfsBackend` to subclass `TrustsOrderedFoldModelBackend`
      once. Keep the AccessCheck `has_perm` intercept.
- [ ] Change `WinfsConfig` to subclass `OrderedFoldImplementationConfig`.
      Keep `trusts_backend_paths = ('winfs.backends.WinfsBackend',)`.
- [ ] Do not list `trusts_ordered_fold.backends.TrustsOrderedFoldModelBackend`
      in `AUTHENTICATION_BACKENDS`.
- [ ] Replace `from trusts.core import OrderedFold, …` with
      `from trusts_ordered_fold import …`. Keep `Along` / `Ref` on Core.
- [ ] Change `register_winfs_policy` to call
      `register_ordered_fold(backend, WinAce, NODE_FOLD)`.
- [ ] Stop treating Core `BackendHandle.register_ordered_fold` as a
      compatibility floor.
- [ ] Replace Core `AuthorizedManager` with the OrderedFold family-local
      manager, or drop it and keep `authorized_nodes`.
- [ ] Treat leftover Core fold imports, `backend.register_ordered_fold(`,
      `TrustModelBackendMixin`, and `trusts.E006` as unfinished
      conversion unless they are historical `migrates.md` rows.
- [ ] `manage.py check` stays clean of `trusts.E001` / `E002` /
      `trusts_ordered_fold.E001`. PostgreSQL is required.
- [ ] Replay V1–V43, depths 63/64/65, fail-closed invalid source rows,
      package/fresh-install proof, `manage.py check`, migrations, and
      the one-query plan tests.

# Migration record — W-methods (#9)

Historical cutover to C-methods `backend.register_ordered_fold`. The
live registration spelling is the W section above.

This consumer paired with `django-trusts>=1.0.0.dev3,<2` at C-methods
merge `f5211c11047eb6810680f5d1b13bf34b2c376635`. Core is a library. Do
not list `'trusts'` in `INSTALLED_APPS`.

## Registration API

Donate through the configured backend and the dedicated OrderedFold
method. Do not call `.registry.register_strategy(...)`, construct
public `Ref` fields on the OrderedFold declaration, or use the
temporary `backend.register(..., strategy=...)` forwarder.

```python
# Old (#3 / 1e19b5d)
registry = owner.configured_backend(CANONICAL_BACKEND).registry
register_winfs_policy(registry)  # registry.register_strategy(NODE_FOLD)

NODE_FOLD = OrderedFold(
    content=Ref(WinNode),
    descriptor=Ref(WinNode).security_descriptor,
    source=Ref(WinAce),
    source_descriptor=Ref(WinAce).descriptor,
    ...
)

# New (C-methods / f5211c11)
backend = owner.configured_backend(CANONICAL_BACKEND)
register_winfs_policy(backend)

backend.register_ordered_fold(
    WinAce,
    OrderedFold(
        content=WinNode,
        descriptor="security_descriptor",
        source_descriptor="descriptor",
        order="ace_order",
        polarity=PolarityMap(
            "ace_type",
            allow_value="allow",
            deny_value="deny",
        ),
        mask="access_mask",
        trustee="trustee_sid",
        token=FlatToken(
            principal=WinPrincipal,
            principal_user="user",
            principal_identity="sid",
            member=WinSidMember,
            member_identity="member_sid",
            member_group="group_sid__sid",
        ),
        domain=PERMISSION_DOMAIN,
    ),
)
```

| | Previous (#3 / `1e19b5d`) | New (C-methods / `f5211c11`) |
| --- | --- | --- |
| Donation host | `registry.register_strategy(OrderedFold(...Ref...))` | `backend.register_ordered_fold(WinAce, OrderedFold(...))` |
| `WinfsConfig.ready()` | inspect registry identity + `register_winfs_policy(registry)` | `backend = configured_backend(...)`; `register_winfs_policy(backend)` |
| `register_winfs_policy(...)` | takes a registry; inspects `registry.strategies` for WinNode | takes the configured backend; idempotent on backend identity; no `.registry` read |
| OrderedFold `content` | `Ref(WinNode)` | `WinNode` |
| OrderedFold `descriptor` | `Ref(WinNode).security_descriptor` | `"security_descriptor"` (content-relative) |
| OrderedFold `source` | `Ref(WinAce)` | derived from the positional `WinAce` argument |
| OrderedFold `source_descriptor` | `Ref(WinAce).descriptor` | `"descriptor"` (source-relative) |
| Temporary forwarder | n/a | do not call `backend.register(..., strategy=...)` |
| Parent bound | `Along(Ref(WinNode).parent, bound=64)` | unchanged; not `register_relationship(..., along=)` |
| Package pin | `1e19b5d464c067186aada58943c3ee67c44b2aa0` | `f5211c11047eb6810680f5d1b13bf34b2c376635` |

The positional model is the source root. `content` is the protected
model class. The two descriptor paths must converge on the same stored
security descriptor (`WinAce.descriptor → SecurityDescriptor ←
WinNode.security_descriptor`). Do not derive one path from the other.

The consumer-owned 64-link parent-recursion bound stays
`INHERITANCE_WALK = Along(Ref(WinNode).parent, bound=64)`. Do not
reinterpret it as AnyPath `along=`.

Registration, duplicate donation, and malformed-declaration checks
remain zero SQL and leave no partial mutation.

## W-methods migration-bot checklist

Search application code, docs, tests, and packaging fixtures for:

```text
.registry
Ref(
register_strategy(
.register(
1e19b5d464c067186aada58943c3ee67c44b2aa0
6cf12d990c65e20dc862ed1dd1db8f8ec4f874be
register_winfs_policy(
```

Then:

- [ ] Install C-methods merge `f5211c11047eb6810680f5d1b13bf34b2c376635`
      (constraint `django-trusts>=1.0.0.dev3,<2`).
- [ ] Change `WinfsConfig.ready()` and `register_winfs_policy(...)` to
      donate through `backend.register_ordered_fold(...)`.
- [ ] Stop passing a registry to `register_winfs_policy`. The argument
      is the configured backend.
- [ ] Remove application-facing `.registry.register_strategy(...)`,
      donation-time registry inspection/idempotency, and public `Ref`
      construction from the OrderedFold declaration.
- [ ] Do not call the temporary `backend.register(..., strategy=...)`
      forwarder.
- [ ] Keep `Along(Ref(WinNode).parent, bound=64)` as the consumer
      parent-walk bound. Do not pass it as
      `register_relationship(..., along=)`.
- [ ] Runtime/compiler-internal `.registry` access
      (`plan_for` / `has_permission`) may remain where the evaluator
      already uses it. Do not use `.registry` for donation
      idempotency.
- [ ] Classify leftover `.registry`, `Ref(`, `register_strategy(`,
      `.register(`, old Core SHAs, and `register_winfs_policy(registry)`
      as unfinished conversion unless they are the consumer Along bound
      or a compiler-internal test fixture.
- [ ] Replay V1–V43, depths 63/64/65, fail-closed invalid source rows,
      package/fresh-install proof, `manage.py check`, migrations, and
      the one-query plan tests.

# Migration record — final core conversion (#3)

Historical cutover from Context / Trustee to OrderedFold. The live
registration spelling is the W section above. Settings, schema, and
evaluator rows below remain current except where W replaced the
backend/import/registration surface.

This consumer pairs with `django-trusts>=1.0.0.dev3,<2`. Core is a
library. Do not list `'trusts'` in `INSTALLED_APPS`.

## 1. Settings and implementation ownership

| | Previous (PR #1 / `b8fff123`) | New |
| --- | --- | --- |
| `INSTALLED_APPS` | `'trusts'` + `winfs.apps.WinfsConfig` | `winfs.apps.WinfsConfig` only |
| `AUTHENTICATION_BACKENDS` | `trusts.backends.TrustModelBackend` | `django.contrib.auth.backends.ModelBackend` then `winfs.backends.WinfsBackend` |
| AppConfig | `django.apps.AppConfig` + `Context.register_*` | `OrderedFoldImplementationConfig` + `trusts_backend_paths` (W) |
| Package | git pin `a2ab5a1` (`1.0.0.dev0`) | `django-trusts>=1.0.0.dev3,<2` at C1 `69348944` plus OrderedFold P2 |

Login is username/password on `ModelBackend`. Object authorization is
the configured mixin backend.

## 2. Registration API (superseded by W)

| | Previous | #3 | W-methods | Live (W) |
| --- | --- | --- | --- | --- |
| Node scope | `Context.register_direct(WinNode, scope_field='security_descriptor')` | `registry.register_strategy(OrderedFold(...))` | `backend.register_ordered_fold(WinAce, OrderedFold(...))` | `register_ordered_fold(backend, WinAce, OrderedFold(...))` |
| Stream sidecar | `Context.register_related(WinStream, through='node')` | `access_check` still resolves `WinStream` to `WinNode`; no second content terminal | unchanged | unchanged |
| Parent bound | `MAX_PARENT_DEPTH = 64` in SQL | `Along(Ref(WinNode).parent, bound=64)` declares the same cap; not `register(along=)` | unchanged; not `register_relationship(..., along=)` | unchanged; this path does not register a relationship |

Along is not a relationship `along=` on `WinNode`. This consumer does
not register a mixed relationship/OrderedFold plan. The Along renderer
is SQLite-only. Windows ACE inheritance (OI/CI/NP/IO,
`SE_DACL_PROTECTED`) is not grant-on-ancestor reachability. The
consumer ancestor CTE uses `Along.bound`.

## 3. Evaluator methods

| Method | Previous | New |
| --- | --- | --- |
| `access_check(user, resource, desired_mask)` | One SQL statement; Context gate | Same signature and V1–V43 outcomes; gate is a live OrderedFold plan; invalid/NULL/negative/>32-bit ACE rows fail closed before applicability (`error=invalid_source`); zero masks stay legal |
| `authorized_pks` / `authorized_nodes` | One SQL statement; filter then `ORDER BY` / `LIMIT` | Unchanged signatures; same one-statement contract |
| `user.has_perm('winfs.<action>_winnode', node)` | Not used (backend installed only for checks) | Mapped through `access_check` only for the full `winfs` / `WinNode` identity. Wrong-app strings (`auth.read_winnode`) and same-codename Permission rows on another content type do not map. Domain actions: `read`, `write`, `execute`, `readwrite`, `list`, `readcontrol`, `writedac`. |
| `WinNode.objects.authorized(user, permission)` | Absent | OrderedFold family-local `AuthorizedManager` is installed; listing proofs stay on `authorized_pks` / `authorized_nodes` so inheritance and owner pre-grant remain one statement |

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
- Application-facing `.registry.register_strategy(...)` and public
  OrderedFold `Ref` construction (see W-methods)
- Core fold-name compatibility floor (`trusts.core.OrderedFold`,
  `BackendHandle.register_ordered_fold`)

An incompatible stack raises `ImproperlyConfigured` from
`winfs.compat.require_ordered_fold()` before the backend or AppConfig
loads.

## #3 migration-bot checklist (historical)

The live checklist is the W section. Historical #3 steps that
remain in force:

- [ ] Remove `'trusts'` / `KernelConfig` from `INSTALLED_APPS`.
- [ ] Replace `TrustModelBackend` with `ModelBackend` plus
      `winfs.backends.WinfsBackend`.
- [ ] Subclass `OrderedFoldImplementationConfig` and set
      `trusts_backend_paths = ('winfs.backends.WinfsBackend',)`.
- [ ] Do not add `register_relationship(..., along=Along(...))` on
      `WinNode`.
- [ ] Call `access_check` / `authorized_pks` / `authorized_nodes` for
      full Windows semantics (inheritance, owner RC\|WD, OWNER_RIGHTS,
      depth/cycle). Do not treat OrderedFold-only `.authorized()` as
      AccessCheck.
- [ ] Map `has_perm` only for the full `winfs` / `WinNode` identity.
      `auth.read_winnode` and a same-codename Permission on another
      content type must not invoke AccessCheck.
- [ ] Run `0003_final_core_token_and_mask`. Refuse NULL
      `WinPrincipal.user` and ACE masks outside `0..0xFFFFFFFF`.
- [ ] `manage.py check` must stay clean of `trusts.E001` / `E002` /
      `trusts_ordered_fold.E001`. PostgreSQL is required for OrderedFold
      evaluate.
- [ ] Replay V1–V43, depths 63/64/65, fail-closed invalid source rows,
      and the one-query plan tests.
- [ ] Do not invent Windows-host oracle results. Catalog rows stay
      documentation-derived until a reviewed host capture exists.
