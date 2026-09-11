# django-trusts-windows-acl migration record

Issue #3 converts the preserved PR #1 evaluator (`b8fff123`) to final
core `django-trusts>=1.0.0.dev3,<2` (merge `1e19b5d`).

## No change to these public call sites

- `access_check(user, resource, desired_mask)` signature and results
- `authorized_pks` / `authorized_nodes` / `explain_access_sql`
- V1–V43 matrix outcomes, depth 63/64/65, ACE-scan cap
- `WinSid` / DACL / `WinNode.parent` table identities (`0001_initial`,
  `0002_postgres_guards`)
- Package version `0.1.0.dev0`

## Changes

### 1. Implementation owner replaces Context / kernel AppConfig

| | |
| --- | --- |
| Previous | `INSTALLED_APPS` listed bare `'trusts'`. `WinfsConfig.ready()` called `Context.register_direct` / `Context.register_related`. `AUTHENTICATION_BACKENDS` was `trusts.backends.TrustModelBackend`. |
| New | Core `'trusts'` is absent. `WinfsConfig` is a `TrustsImplementationConfig` owning `winfs.backends.WinfsAuthorizationBackend`. Login is `django.contrib.auth.backends.ModelBackend`. `ready()` registers `OrderedFold` on the owner registry. Missing `TrustsImplementationConfig` raises `ImproperlyConfigured` (`django-trusts>=1.0.0.dev3,<2`). |
| Replacement | Do not install a core AppConfig. Do not import `trusts.context` or `trusts.trustee`. |
| Authorization | Unregistered models still fail closed (`ERR_CONTEXT`). WinNode / WinStream still require a live owner + OrderedFold plan. |

### 2. Explicit-DACL OrderedFold beside the preserved CTE

| | |
| --- | --- |
| Previous | Remaining-bits AccessCheck lived only in the Windows PostgreSQL CTE. |
| New | `registry.register_strategy(OrderedFold(...))` compiles explicit-DACL remaining-bits through the same `Allowed` predicate used by `has_permission` and `WinNode.objects.authorized`. The preserved CTE still evaluates inheritance, OI/CI/NP/IO, `CREATOR_OWNER`, `OWNER_RIGHTS`, owner pre-grant, and cycle/depth. Along models the 64-parent bound but has no PostgreSQL renderer, so it is not the production inheritance walk. |
| Replacement | Callers that need the full V1–V43 oracle keep `access_check` / `authorized_*`. Callers that need Trusts-compiled explicit DACL use `registry.has_permission` / `.authorized` with a `Permission` instance (`read_winnode`, `write_winnode`, `rc_winnode`, `wd_winnode`). |
| Authorization | An OrderedFold deny is local to this policy set. It does not veto unrelated Django backends. Invalid / NULL / negative source rows fail closed before applicability. |

### 3. `WinPrincipal.user` is required

| | |
| --- | --- |
| Previous | `WinPrincipal.user` was nullable. |
| New | Non-null `OneToOneField` (migration `0003_principal_user_required`). OrderedFold Token `principal_user` cannot walk a nullable field. Seeded and fixture principals already had users. |
| Authorization | No change to AccessCheck results. A principal without a login user cannot be created. |

## V1–V43 mapping

| Family | Path |
| --- | --- |
| Explicit stored-order allow/deny, bits, user/group token (V1–V16 except owner seed / OWNER_RIGHTS) | Preserved CTE + OrderedFold agreement proofs |
| Inheritance, OI/CI/NP/IO, protected DACL (V17–V31, V39) | Preserved CTE (Along cannot render on PostgreSQL) |
| Owner RC\|WD pre-grant, OWNER_RIGHTS (V14–V16, V40–V43) | Preserved CTE (Windows-owned semantics) |
| Cycle / depth 63/64/65 / ACE-scan / missing principal (V36–V38′) | Preserved CTE; Along declaration records the 64-hop bound |

## Migration-bot checklist

- [ ] Remove `'trusts'` / `trusts.apps.KernelConfig` / `trusts.apps.AppConfig` from `INSTALLED_APPS`.
- [ ] Replace `trusts.backends.TrustModelBackend` with `django.contrib.auth.backends.ModelBackend` plus `winfs.backends.WinfsAuthorizationBackend`.
- [ ] Pin `django-trusts>=1.0.0.dev3,<2`. Pair CI uses merge `1e19b5d`.
- [ ] Delete `from trusts.context import Context` and `from trusts.trustee import Trustee`.
- [ ] Confirm `WinfsConfig` subclasses `TrustsImplementationConfig` and `ready()` calls `super().ready()` then `register_explicit_dacl`.
- [ ] Apply `0003_principal_user_required` before creating principals.
- [ ] Run `python manage.py check` and `python manage.py test winfs` on PostgreSQL 16.
- [ ] Keep `access_check` for the full matrix; use `.authorized` / `has_permission` only for explicit-DACL Trusts projections.
