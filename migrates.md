# Migration record — W-methods (#9)

This consumer now pairs with `django-trusts>=1.0.0.dev3,<2` at C-methods
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
registration spelling is the W-methods section above. Settings,
schema, and evaluator rows below remain current.

This consumer pairs with `django-trusts>=1.0.0.dev3,<2`. Core is a
library. Do not list `'trusts'` in `INSTALLED_APPS`.

## 1. Settings and implementation ownership

| | Previous (PR #1 / `b8fff123`) | New |
| --- | --- | --- |
| `INSTALLED_APPS` | `'trusts'` + `winfs.apps.WinfsConfig` | `winfs.apps.WinfsConfig` only |
| `AUTHENTICATION_BACKENDS` | `trusts.backends.TrustModelBackend` | `django.contrib.auth.backends.ModelBackend` then `winfs.backends.WinfsBackend` |
| AppConfig | `django.apps.AppConfig` + `Context.register_*` | `TrustsImplementationConfig` + `trusts_backend_paths` |
| Package | git pin `a2ab5a1` (`1.0.0.dev0`) | `django-trusts>=1.0.0.dev3,<2` at `f5211c11` |

Login is username/password on `ModelBackend`. Object authorization is
the configured mixin backend.

## 2. Registration API (superseded by W-methods)

| | Previous | #3 | Live (W-methods) |
| --- | --- | --- | --- |
| Node scope | `Context.register_direct(WinNode, scope_field='security_descriptor')` | `registry.register_strategy(OrderedFold(...))` | `backend.register_ordered_fold(WinAce, OrderedFold(...))` |
| Stream sidecar | `Context.register_related(WinStream, through='node')` | `access_check` still resolves `WinStream` to `WinNode`; no second content terminal | unchanged |
| Parent bound | `MAX_PARENT_DEPTH = 64` in SQL | `Along(Ref(WinNode).parent, bound=64)` declares the same cap; not `register(along=)` | unchanged; not `register_relationship(..., along=)` |

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
- Application-facing `.registry.register_strategy(...)` and public
  OrderedFold `Ref` construction (see W-methods)

An incompatible core raises `ImproperlyConfigured` from
`winfs.compat.require_final_core()` before the backend or AppConfig
loads.

## #3 migration-bot checklist (historical)

The live checklist is the W-methods section. Historical #3 steps that
remain in force:

- [ ] Remove `'trusts'` / `KernelConfig` from `INSTALLED_APPS`.
- [ ] Replace `TrustModelBackend` with `ModelBackend` plus
      `winfs.backends.WinfsBackend`.
- [ ] Subclass `TrustsImplementationConfig` and set
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
- [ ] `manage.py check` must stay clean of `trusts.E001` / `E002`.
      PostgreSQL is required for OrderedFold evaluate (`trusts.E006`).
- [ ] Replay V1–V43, depths 63/64/65, fail-closed invalid source rows,
      and the one-query plan tests.
- [ ] Do not invent Windows-host oracle results. Catalog rows stay
      documentation-derived until a reviewed host capture exists.
